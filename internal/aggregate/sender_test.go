package aggregate

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

type cloud struct {
	mu       sync.Mutex
	statuses []int // answered in turn; the last one repeats
	got      []Batch
	headers  []http.Header
}

func (c *cloud) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()

	status := c.statuses[0]
	if len(c.statuses) > 1 {
		c.statuses = c.statuses[1:]
	}
	c.headers = append(c.headers, r.Header.Clone())

	zr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "not gzip", 400)
		return
	}
	var b Batch
	if err := json.NewDecoder(zr).Decode(&b); err != nil {
		http.Error(w, "not json", 400)
		return
	}
	c.got = append(c.got, b)
	w.WriteHeader(status)
}

func testSender(t *testing.T, url string, ids ...string) *sender {
	t.Helper()
	box, err := openOutbox(t.TempDir(), OutboxLimit, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		body, _ := encodeBatch(&Batch{Format: 1, Batch: id, Node: testNode, SentAt: "2026-09-08T17:20:00Z", Rows: []Row{}})
		if err := box.put(id, body); err != nil {
			t.Fatal(err)
		}
	}
	return &sender{
		url: url, token: "tok", node: testNode, version: "0.2.0",
		client: newClient(), outbox: box, log: slog.Default(),
		wake: make(chan struct{}, 1),
	}
}

const testNode = "8f14e45fceea167a5a36dedd4bea2543"

func left(t *testing.T, s *sender) []string {
	t.Helper()
	ids, err := s.outbox.list()
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

func TestAcceptedIsRemovedOldestFirst(t *testing.T) {
	c := &cloud{statuses: []int{202}}
	srv := httptest.NewServer(c)
	defer srv.Close()

	s := testSender(t, srv.URL, "b-2", "b-1", "b-3")
	if d := s.drain(t.Context()); d != 0 {
		t.Fatalf("delay %s after everything was taken", d)
	}
	if ids := left(t, s); len(ids) != 0 {
		t.Fatalf("left in the outbox: %v", ids)
	}
	if len(c.got) != 3 || c.got[0].Batch != "b-1" || c.got[2].Batch != "b-3" {
		t.Fatalf("order: %+v", c.got)
	}

	h := c.headers[0]
	for k, want := range map[string]string{
		"Authorization":     "Bearer tok",
		"Content-Type":      "application/json",
		"Content-Encoding":  "gzip",
		"X-Antibot-Node":    testNode,
		"X-Antibot-Version": "0.2.0",
	} {
		if got := h.Get(k); got != want {
			t.Errorf("%s: %q, want %q", k, got, want)
		}
	}
}

// 400 is not retried: the same bytes would get the same answer, and a
// batch stuck at the head would hold back everything behind it.
func TestRejectedIsDroppedAndTheRestGoes(t *testing.T) {
	c := &cloud{statuses: []int{400, 202}}
	srv := httptest.NewServer(c)
	defer srv.Close()

	s := testSender(t, srv.URL, "b-1", "b-2")
	if d := s.drain(t.Context()); d != 0 {
		t.Fatalf("delay %s", d)
	}
	if ids := left(t, s); len(ids) != 0 {
		t.Fatalf("left: %v", ids)
	}
	if len(c.got) != 2 {
		t.Fatalf("%d posts, want 2", len(c.got))
	}
}

func TestRefusedTokenSleepsAnHour(t *testing.T) {
	for _, status := range []int{401, 403} {
		c := &cloud{statuses: []int{status}}
		srv := httptest.NewServer(c)

		s := testSender(t, srv.URL, "b-1", "b-2")
		if d := s.drain(t.Context()); d != time.Hour {
			t.Errorf("%d: delay %s, want an hour", status, d)
		}
		if ids := left(t, s); len(ids) != 2 {
			t.Errorf("%d: the outbox lost batches: %v", status, ids)
		}
		if len(c.got) != 1 {
			t.Errorf("%d: %d posts, want to stop at the first", status, len(c.got))
		}
		srv.Close()
	}
}

// 429 and 5xx grow the delay 1, 2, 4… minutes up to half an hour, and
// a success resets it.
func TestBackoffGrowsAndResets(t *testing.T) {
	c := &cloud{statuses: []int{503}}
	srv := httptest.NewServer(c)
	defer srv.Close()

	s := testSender(t, srv.URL, "b-1")
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for i, w := range want {
		if d := s.drain(t.Context()); d != w*time.Minute {
			t.Fatalf("attempt %d: delay %s, want %s", i+1, d, w*time.Minute)
		}
	}
	if ids := left(t, s); len(ids) != 1 {
		t.Fatalf("the batch was lost while retrying: %v", ids)
	}

	c.mu.Lock()
	c.statuses = []int{429, 202}
	c.mu.Unlock()
	s.drain(t.Context())
	if d := s.drain(t.Context()); d != 0 || s.failures != 0 {
		t.Fatalf("after success: delay %s, failures %d", d, s.failures)
	}
}

// The cloud cannot move the conversation elsewhere: a redirect would
// carry the subscription token to a foreign host.
func TestRedirectIsNotFollowed(t *testing.T) {
	foreign := &cloud{statuses: []int{202}}
	elsewhere := httptest.NewServer(foreign)
	defer elsewhere.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	s := testSender(t, srv.URL, "b-1")
	if d := s.drain(t.Context()); d == 0 {
		t.Fatal("a redirect counted as delivery")
	}
	if len(foreign.got) != 0 {
		t.Fatal("the redirect was followed, and the token went with it")
	}
}

func TestUnreachableCloudKeepsTheBatch(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()

	s := testSender(t, url, "b-1")
	if d := s.drain(t.Context()); d != time.Minute {
		t.Fatalf("delay %s", d)
	}
	if ids := left(t, s); len(ids) != 1 {
		t.Fatalf("left: %v", ids)
	}
}
