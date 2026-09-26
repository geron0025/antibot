package proposals

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/schemacheck"
)

func TestFeedbackURLDerivation(t *testing.T) {
	cases := map[string]string{
		"https://x/ingest":  "https://x/proposals/feedback",
		"https://x":         "https://x/proposals/feedback",
		"https://x/":        "https://x/proposals/feedback",
		"https://x/ingest/": "https://x/proposals/feedback",
	}
	for in, want := range cases {
		if got := FeedbackURL(in); got != want {
			t.Errorf("FeedbackURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func boolPtr(b bool) *bool { return &b }

// computeItems turns decisions and the rule set as it stands now into
// exactly one item per proposal or advice — the state it is in right
// now, not a history of how it got there.
func TestComputeItems(t *testing.T) {
	acceptedAt := time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)

	activeRule := rules.Rule{ID: "cloud-active", Mode: rules.Active,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block}}
	shadowRule := rules.Rule{ID: "cloud-shadow", Mode: rules.Shadow,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block}}
	disabledRule := rules.Rule{ID: "cloud-disabled", Mode: rules.Active, Enabled: boolPtr(false),
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block}}
	adviceRuleShadow := rules.Rule{ID: "owner-shadow", Mode: rules.Shadow,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"isp"`)},
		Action:    rules.Action{Type: rules.Block}}
	adviceRuleActive := rules.Rule{ID: "owner-active", Mode: rules.Active,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"isp"`)},
		Action:    rules.Action{Type: rules.Block}}

	current := []rules.Rule{activeRule, shadowRule, disabledRule, adviceRuleShadow}

	decisions := []Decision{
		{ID: "cloud-active", Accepted: true, At: acceptedAt},
		{ID: "cloud-shadow", Accepted: true, At: acceptedAt},
		{ID: "cloud-disabled", Accepted: true, At: acceptedAt},
		{ID: "cloud-removed", Accepted: true, At: acceptedAt},
		{ID: "cloud-declined", Accepted: false, At: acceptedAt, Reason: "our own partners"},
	}

	advice := []Advice{
		{ID: "cloud-advice-disable-done", Rule: adviceRuleShadow.Hash(), Suggest: SuggestShadow},
		{ID: "cloud-advice-disable-not-done", Rule: adviceRuleActive.Hash(), Suggest: SuggestDisable},
		{ID: "cloud-advice-gone", Rule: "0000000000000000", Suggest: SuggestReview},
	}

	items := computeItems(now, decisions, current, advice)
	byID := map[string]Item{}
	for _, it := range items {
		byID[it.ID] = it
	}

	want := map[string]string{
		"cloud-active":                  StateActive,
		"cloud-shadow":                  StateAccepted,
		"cloud-disabled":                StateDisabled,
		"cloud-removed":                 StateRemoved,
		"cloud-declined":                StateRejected,
		"cloud-advice-disable-done":     StateDone, // suggested shadow, and it is
		"cloud-advice-disable-not-done": "",        // suggested disable, still active: not done
		"cloud-advice-gone":             StateDone, // the rule is gone
	}
	for id, state := range want {
		it, ok := byID[id]
		if state == "" {
			if ok {
				t.Errorf("%s: reported %q, want nothing yet", id, it.State)
			}
			continue
		}
		if !ok {
			t.Errorf("%s: missing from the answer", id)
			continue
		}
		if it.State != state {
			t.Errorf("%s: state %q, want %q", id, it.State, state)
		}
	}

	if it := byID["cloud-shadow"]; it.At != acceptedAt {
		t.Errorf("cloud-shadow: at %v, want the moment it was accepted %v", it.At, acceptedAt)
	}
	if it := byID["cloud-active"]; it.At != now {
		t.Errorf("cloud-active: at %v, want the moment this was noticed %v", it.At, now)
	}
	if it := byID["cloud-declined"]; it.Reason != "our own partners" {
		t.Errorf("cloud-declined: reason %q", it.Reason)
	}
}

// An advice can be rejected — docs/*/protocol/proposals.md «Ответ ноды»
// shows exactly that, with a reason — and once it is, computeItems must
// report only the rejection, never a later "done", even when the rule
// the advice is about happens to satisfy the "done" condition on its
// own: the owner declined the advice, not merely delayed acting on it.
func TestComputeItemsRejectedAdviceNeverTurnsDone(t *testing.T) {
	rejectedAt := time.Date(2026, 9, 10, 9, 5, 0, 0, time.UTC)
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)

	// Disabled, which is exactly what SuggestDisable's "done" condition
	// looks for — and must be ignored because the advice was rejected.
	disabledRule := rules.Rule{ID: "owner-rule", Mode: rules.Active, Enabled: boolPtr(false),
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block}}
	current := []rules.Rule{disabledRule}

	decisions := []Decision{
		{ID: "cloud-advice-cuts-people-2026-09", Accepted: false, At: rejectedAt,
			Reason: "это наши партнёры, так и задумано"},
	}
	advice := []Advice{
		{ID: "cloud-advice-cuts-people-2026-09", Rule: disabledRule.Hash(), Suggest: SuggestDisable},
	}

	items := computeItems(now, decisions, current, advice)
	if len(items) != 1 {
		t.Fatalf("expected exactly one item (the rejection, not a later done too), got %d: %+v",
			len(items), items)
	}
	it := items[0]
	if it.ID != "cloud-advice-cuts-people-2026-09" || it.State != StateRejected ||
		it.At != rejectedAt || it.Reason != "это наши партнёры, так и задумано" {
		t.Fatalf("wrong item: %+v", it)
	}
}

// feedbackServer captures posts and answers a fixed status.
type feedbackServer struct {
	status  int
	posts   [][]byte
	headers []http.Header
}

func (s *feedbackServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body []byte
		if r.Header.Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err == nil {
				body, _ = io.ReadAll(zr)
			}
		} else {
			body, _ = io.ReadAll(r.Body)
		}
		s.posts = append(s.posts, body)
		s.headers = append(s.headers, r.Header.Clone())
		status := s.status
		if status == 0 {
			status = http.StatusAccepted
		}
		w.WriteHeader(status)
	})
}

func newSender(t *testing.T, srv *feedbackServer, decisions *Store, rulesStore *rules.Store, stateDir string) *Sender {
	t.Helper()
	server := httptest.NewServer(srv.handler())
	t.Cleanup(server.Close)
	return &Sender{
		URL: server.URL, Token: "the-token", NodeID: testNodeID, Version: "0.1.0",
		Decisions: decisions, Rules: rulesStore, StateDir: stateDir, Log: quietLog(),
	}
}

func decodeFeedback(t *testing.T, raw []byte) Feedback {
	t.Helper()
	var fb Feedback
	if err := json.Unmarshal(raw, &fb); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	if errs := schemacheck.Validate(proposalFeedbackSchema, generic); len(errs) > 0 {
		t.Fatalf("feedback body does not pass its schema: %v", errs)
	}
	return fb
}

// One accepted proposal, promoted to active, then deleted: each state
// change produces exactly one post with exactly the one item that
// changed, and an accepted post is never sent again.
func TestSenderSendsOneChangePerCycle(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)
	decisionsStore := Open(dir)

	writeProposalsDoc(t, dir, Document{Node: testNodeID, Proposals: []Proposal{sampleProposal("cloud-p")}})
	if err := decisionsStore.Accept("cloud-p", rulesStore, "owner", time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}

	srv := &feedbackServer{}
	stateDir := t.TempDir()
	sender := newSender(t, srv, decisionsStore, rulesStore, stateDir)
	sender.now = func() time.Time { return time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) }

	if err := sender.Once(context.Background()); err != nil {
		t.Fatalf("first cycle: %v", err)
	}
	if len(srv.posts) != 1 {
		t.Fatalf("expected one post, got %d", len(srv.posts))
	}
	fb := decodeFeedback(t, srv.posts[0])
	if len(fb.Items) != 1 || fb.Items[0].ID != "cloud-p" || fb.Items[0].State != StateAccepted {
		t.Fatalf("first post: %+v", fb.Items)
	}

	// Nothing changed: no second post.
	if err := sender.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 1 {
		t.Fatalf("an unchanged state was resent: %d posts", len(srv.posts))
	}

	// The owner promotes the rule to active.
	if err := rulesStore.SetMode("cloud-p", rules.Active); err != nil {
		t.Fatal(err)
	}
	sender.now = func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }
	if err := sender.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 2 {
		t.Fatalf("expected a second post after promotion, got %d", len(srv.posts))
	}
	fb = decodeFeedback(t, srv.posts[1])
	if len(fb.Items) != 1 || fb.Items[0].State != StateActive {
		t.Fatalf("second post: %+v", fb.Items)
	}

	// The owner deletes the rule.
	if err := rulesStore.Remove("cloud-p"); err != nil {
		t.Fatal(err)
	}
	if err := sender.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 3 {
		t.Fatalf("expected a third post after removal, got %d", len(srv.posts))
	}
	fb = decodeFeedback(t, srv.posts[2])
	if len(fb.Items) != 1 || fb.Items[0].State != StateRemoved {
		t.Fatalf("third post: %+v", fb.Items)
	}
}

// A 5xx is retried with the same changes; a 2xx is never resent.
func TestSenderRetriesOn5xxThenSucceeds(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)
	decisionsStore := Open(dir)
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Proposals: []Proposal{sampleProposal("cloud-p")}})
	if err := decisionsStore.Reject("cloud-p", "no thanks", "owner", time.Now()); err != nil {
		t.Fatal(err)
	}

	srv := &feedbackServer{status: http.StatusInternalServerError}
	stateDir := t.TempDir()
	sender := newSender(t, srv, decisionsStore, rulesStore, stateDir)

	if err := sender.Once(context.Background()); err == nil {
		t.Fatal("a 5xx was treated as success")
	}
	if len(srv.posts) != 1 {
		t.Fatalf("expected one attempt, got %d", len(srv.posts))
	}
	first := decodeFeedback(t, srv.posts[0])

	// Retried: the state was not marked sent, so the same change goes
	// out again.
	srv.status = 0 // 202 this time
	if err := sender.Once(context.Background()); err != nil {
		t.Fatalf("the retried cycle failed: %v", err)
	}
	if len(srv.posts) != 2 {
		t.Fatalf("expected a second attempt, got %d", len(srv.posts))
	}
	second := decodeFeedback(t, srv.posts[1])
	if second.Items[0].ID != first.Items[0].ID || second.Items[0].State != first.Items[0].State {
		t.Fatalf("the retried post carried a different change: %+v vs %+v", first.Items, second.Items)
	}

	// Now accepted: nothing more to send.
	if err := sender.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.posts) != 2 {
		t.Fatalf("an accepted report was resent: %d posts", len(srv.posts))
	}
}

// The gzip'd, authenticated request the cloud expects.
func TestSenderRequestShape(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)
	decisionsStore := Open(dir)
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Proposals: []Proposal{sampleProposal("cloud-p")}})
	if err := decisionsStore.Reject("cloud-p", "", "owner", time.Now()); err != nil {
		t.Fatal(err)
	}

	srv := &feedbackServer{}
	sender := newSender(t, srv, decisionsStore, rulesStore, t.TempDir())
	if err := sender.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.headers) != 1 {
		t.Fatal("no request was made")
	}
	h := srv.headers[0]
	if h.Get("Authorization") != "Bearer the-token" {
		t.Errorf("authorization: %q", h.Get("Authorization"))
	}
	if h.Get("X-Antibot-Node") != testNodeID {
		t.Errorf("node header: %q", h.Get("X-Antibot-Node"))
	}
	if h.Get("Content-Encoding") != "gzip" {
		t.Errorf("content-encoding: %q", h.Get("Content-Encoding"))
	}
}
