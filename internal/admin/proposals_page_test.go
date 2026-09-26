package admin

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/proposals"
	"github.com/geron0025/antibot/internal/rules"
)

// proposalsFixture is the cloud's list as it would arrive after
// internal/proposals.Fetcher checked it: one live proposal, one piece of
// advice about adviceRuleHash — newServer's own "block-curl" rule, in
// every test that uses it — and one expired proposal that must never be
// shown.
func proposalsFixture(t *testing.T, dir string, adviceRuleHash string, now time.Time) {
	t.Helper()
	doc := map[string]any{
		"format":     1,
		"node":       "8f14e45fceea167a5a36dedd4bea2543",
		"created_at": now.UTC().Format(time.RFC3339),
		"proposals": []any{
			map[string]any{
				"id":         "cloud-hosting-no-browser-2026-09",
				"created_at": now.Add(-time.Hour).UTC().Format(time.RFC3339),
				"expires_at": now.Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"rule": map[string]any{
					"id":       "cloud-hosting-no-browser-2026-09",
					"name":     "hosting without a browser handshake",
					"scope":    []any{"*"},
					"priority": 100,
					"condition": map[string]any{
						"all": []any{
							map[string]any{"field": "network.class", "op": "eq", "value": "hosting"},
							map[string]any{"field": "ua_matches_ja4", "op": "eq", "value": false},
						},
					},
					"action": map[string]any{"type": "block", "status": 403},
				},
				"why": "4128 requests over a week from hosting networks naming themselves Chrome.",
				"evidence": map[string]any{
					"window": "2026-09-02/2026-09-09", "requests": 4128, "share": 0.021,
					"networks": 6, "addresses": 143,
					"would_block": 4128, "would_block_protected": 0,
				},
			},
			map[string]any{
				"id":         "cloud-expired-2026-08",
				"created_at": now.Add(-60 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"expires_at": now.Add(-24 * time.Hour).UTC().Format(time.RFC3339),
				"rule": map[string]any{
					"id": "cloud-expired-2026-08", "scope": []any{"*"}, "priority": 1,
					"condition": map[string]any{"field": "ua", "op": "contains", "value": "bot"},
					"action":    map[string]any{"type": "block"},
				},
				"why":      "long gone",
				"evidence": map[string]any{"window": "w", "requests": 1, "share": 0.001, "would_block": 1, "would_block_protected": 0},
			},
		},
		"advice": []any{
			map[string]any{
				"id":         "cloud-advice-cuts-people-2026-09",
				"created_at": now.Add(-time.Hour).UTC().Format(time.RFC3339),
				"expires_at": now.Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"rule":       adviceRuleHash,
				"suggest":    "disable",
				"why":        "3104 requests over a week, most of them carrying a cookie.",
				"evidence": map[string]any{
					"window": "2026-09-02/2026-09-09", "requests": 3104, "share": 0.016,
					"with_cookie": 2870, "protected": 0,
				},
			},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, proposals.FileName), raw, 0o640); err != nil {
		t.Fatal(err)
	}
}

// withProposals opens a proposals.Store in the same shared directory as
// s's rules, and drops the fixture above into it, naming its advice after
// the hash "block-curl" — newServer's own rule — has right now.
func withProposals(t *testing.T, s *Server, dir string) {
	t.Helper()
	s.o.Proposals = proposals.Open(dir)

	var hash string
	for _, r := range s.o.Rules.Set().All() {
		if r.ID == "block-curl" {
			hash = r.Hash()
		}
	}
	if hash == "" {
		t.Fatal("block-curl is not in the fixture rules")
	}
	proposalsFixture(t, dir, hash, time.Now())
}

func newProposalsServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, dir := newServer(t)
	withProposals(t, s, dir)
	return s, dir
}

// The tab shows a live proposal and a piece of advice in full — the rule
// rendered readably, the numbers in words, both buttons — and hides what
// expired.
func TestProposalsPageShowsProposalsAndAdvice(t *testing.T) {
	s, _ := newProposalsServer(t)
	cookies := logIn(t, s)
	resp := get(t, s, "/rules/proposals", cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	page := string(body)

	for _, want := range []string{
		"cloud-hosting-no-browser-2026-09",
		"hosting without a browser handshake",
		"4128 requests over a week from hosting networks naming themselves Chrome.",
		"4,128", // requests and would_block, grouped
		"143",   // addresses
		"2.1%",  // share
		`name="do" value="accept"`,
		`name="do" value="reject"`,
		`name="reason"`,
		"cloud-advice-cuts-people-2026-09",
		"block-curl", // the owner's own rule id the advice names
		"3,104",
		"3104 requests over a week, most of them carrying a cookie.",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the tab lacks %q", want)
		}
	}
	if strings.Contains(page, "cloud-expired-2026-08") {
		t.Error("an expired proposal is shown")
	}
}

// Without a store connected the tab still renders — it says so — rather
// than erroring out: exactly like the crawlers tab without its file.
func TestProposalsPageWithoutAStore(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)
	if resp := get(t, s, "/rules/proposals", cookies); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// Accepting writes the rule into rules.json in shadow — it counts
// nothing and blocks nothing until the owner moves it to active himself —
// asks the core to reread, and a second decision on the same id is
// refused.
func TestAcceptProposal(t *testing.T) {
	s, dir := newProposalsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	reloaded := false
	local(s).Reloaders = map[control.Reloadable]func() error{
		control.ReloadRules: func() error { reloaded = true; return nil },
	}

	rec := postForm(t, s, "/rules/proposals", cookies, url.Values{
		"csrf": {csrf}, "id": {"cloud-hosting-no-browser-2026-09"}, "do": {"accept"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("accept: %d %s", rec.Code, rec.Body)
	}
	if !reloaded {
		t.Error("the core was not told to reread the rules")
	}

	list, err := rules.Read(filepath.Join(dir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	var found *rules.Rule
	for i := range list {
		if list[i].ID == "cloud-hosting-no-browser-2026-09" {
			found = &list[i]
		}
	}
	if found == nil || found.Mode != rules.Shadow {
		t.Fatalf("the accepted rule is not in shadow: %+v", list)
	}

	rec = postForm(t, s, "/rules/proposals", cookies, url.Values{
		"csrf": {csrf}, "id": {"cloud-hosting-no-browser-2026-09"}, "do": {"accept"},
	})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("a second decision: %d %v", rec.Code, rec.Header())
	}
}

// Rejecting records the owner's own reason — signed so that it is clear
// the cloud reads it — in proposal-decisions.json.
func TestRejectProposalWithReason(t *testing.T) {
	s, dir := newProposalsServer(t)
	cookies := logIn(t, s)

	rec := postForm(t, s, "/rules/proposals", cookies, url.Values{
		"csrf": {tokenFrom(cookies)}, "id": {"cloud-advice-cuts-people-2026-09"}, "do": {"reject"},
		"reason": {"this is our partner and it is meant to be this way"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body)
	}

	raw, err := os.ReadFile(filepath.Join(dir, proposals.DecisionsFileName))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "this is our partner") {
		t.Errorf("the reason is not in the decisions file: %s", raw)
	}
}

// A forged form decides nothing.
func TestProposalsMissingCSRF(t *testing.T) {
	s, _ := newProposalsServer(t)
	cookies := logIn(t, s)
	rec := postForm(t, s, "/rules/proposals", cookies, url.Values{
		"id": {"cloud-hosting-no-browser-2026-09"}, "do": {"accept"},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("without csrf: %d", rec.Code)
	}
}

// An id that is not in the current list — withdrawn, never sent, or
// mistyped — is a message the owner reads, in his own language.
func TestProposalsUnknownID(t *testing.T) {
	s, _ := newProposalsServer(t)
	cookies := withLang(logIn(t, s), "ru")
	rec := postForm(t, s, "/rules/proposals", cookies, url.Values{
		"csrf": {tokenFrom(cookies)}, "id": {"cloud-does-not-exist"}, "do": {"accept"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("%d", rec.Code)
	}
	resp := get(t, s, rec.Header().Get("Location"), cookies)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "cloud-does-not-exist") {
		t.Errorf("the error does not name the id: %s", body)
	}
}

// The reason is capped at 500 runes, the same limit the wire carries: a
// longer one is refused here, where the owner can see it happen.
func TestProposalsReasonTooLong(t *testing.T) {
	s, _ := newProposalsServer(t)
	cookies := logIn(t, s)
	rec := postForm(t, s, "/rules/proposals", cookies, url.Values{
		"csrf": {tokenFrom(cookies)}, "id": {"cloud-advice-cuts-people-2026-09"}, "do": {"reject"},
		"reason": {strings.Repeat("a", 501)},
	})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
}

// The rules page carries a small notice, linking to the tab, next to the
// rule whose hash the advice names.
func TestAdviceNoticeOnRulesPage(t *testing.T) {
	s, _ := newProposalsServer(t)
	cookies := logIn(t, s)
	resp := get(t, s, "/rules", cookies)
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	if !strings.Contains(page, `/rules/proposals#cloud-advice-cuts-people-2026-09`) {
		t.Errorf("no advice notice linking to the tab: %s", page)
	}
}
