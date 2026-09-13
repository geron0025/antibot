package admin

import (
	"bufio"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/facts"
)

// The page of one rule counts only what that rule touched, and its buttons
// bring the human back to it.
func TestRulePage(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	resp := get(t, s, "/rule?id=block-curl", cookies)
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d %s", resp.StatusCode, page)
	}
	for _, want := range []string{"block-curl", "198.51.100.9", "curl/8.4", "decided or marked",
		"50.0% of all", "&#34;condition&#34;", "/events?ip=198.51.100.9&amp;rule=block-curl"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not contain %q", want)
		}
	}
	// The other request of the log — Googlebot's — is not this rule's.
	if strings.Contains(page, "203.0.113.1") {
		t.Error("the rule's page shows a request it never touched")
	}

	if resp := get(t, s, "/rule?id=nothing", cookies); resp.StatusCode != http.StatusSeeOther ||
		!strings.Contains(resp.Header.Get("Location"), "error") {
		t.Fatalf("a rule that is not there: %d %v", resp.StatusCode, resp.Header)
	}

	rec := alertsPost(t, s, cookies, "/rules/toggle", url.Values{"id": {"block-curl"}, "enable": {"no"}, "back": {"block-curl"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/rule?id=block-curl" {
		t.Fatalf("toggle from the rule's page: %d %v", rec.Code, rec.Header())
	}
	// The field names a rule, never an address.
	rec = alertsPost(t, s, cookies, "/rules/toggle", url.Values{"id": {"block-curl"}, "enable": {"yes"},
		"back": {"https://evil.example/"}})
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/rule?id=") {
		t.Fatalf("back led to %q", loc)
	}
}

// The export hands out the log's own lines, filtered, and nothing else.
func TestEventsExport(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	if resp := get(t, s, "/events/export", nil); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("without a login: %d", resp.StatusCode)
	}

	resp := get(t, s, "/events/export?decision=block&period=1h", cookies)
	if resp.StatusCode != http.StatusOK ||
		!strings.HasPrefix(resp.Header.Get("Content-Type"), "application/x-ndjson") ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	var lines []facts.Request
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var ev facts.Request
		if err := json.Unmarshal(scanner.Bytes(), &ev); err != nil {
			t.Fatalf("not an event line: %q", scanner.Text())
		}
		lines = append(lines, ev)
	}
	if len(lines) != 1 || lines[0].Rule != "block-curl" {
		t.Fatalf("%+v", lines)
	}

	all := get(t, s, "/events/export?period=1h", cookies)
	body, _ := io.ReadAll(all.Body)
	if n := strings.Count(string(body), "\n"); n != 2 {
		t.Fatalf("%d lines without a filter", n)
	}

	none := get(t, s, "/events/export?ip=192.0.2.1", cookies)
	body, _ = io.ReadAll(none.Body)
	if none.StatusCode != http.StatusOK || len(body) != 0 || none.Header.Get("Content-Disposition") == "" {
		t.Fatalf("nothing matched: %d %q %v", none.StatusCode, body, none.Header)
	}

	// The events page offers the download with its own filters.
	page, _ := io.ReadAll(get(t, s, "/events?decision=block", cookies).Body)
	if !strings.Contains(string(page), "/events/export?decision=block&amp;period=24h") {
		t.Fatal("the events page does not offer the download of its filters")
	}
}
