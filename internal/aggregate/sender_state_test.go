package aggregate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The sender remembers when a batch last went through and how the last
// attempt failed: the overview says it without anybody reading the log.
func TestSenderRemembersTheLastAttempt(t *testing.T) {
	code := http.StatusAccepted
	cloud := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
	defer cloud.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	box, err := openOutbox(t.TempDir(), 10, log)
	if err != nil {
		t.Fatal(err)
	}
	s := &sender{url: cloud.URL, token: "t", client: newClient(), outbox: box, log: log,
		wake: make(chan struct{}, 1)}
	ctx := context.Background()

	if sent, problem := s.state(); !sent.IsZero() || problem != "" {
		t.Fatalf("before anything: %v %q", sent, problem)
	}

	box.put("batch-1", []byte("{}"))
	s.drain(ctx)
	sent, problem := s.state()
	if sent.IsZero() || problem != "" {
		t.Fatalf("accepted: %v %q", sent, problem)
	}

	code = http.StatusUnauthorized
	box.put("batch-2", []byte("{}"))
	s.drain(ctx)
	if again, problem := s.state(); !again.Equal(sent) || !strings.Contains(problem, "token (401)") {
		t.Fatalf("refused token: %v %q", again, problem)
	}

	code = http.StatusServiceUnavailable
	s.drain(ctx)
	if _, problem := s.state(); !strings.Contains(problem, "(503)") {
		t.Fatalf("cloud down: %q", problem)
	}

	code = http.StatusAccepted
	s.drain(ctx)
	if later, problem := s.state(); !later.After(sent) || problem != "" {
		t.Fatalf("back: %v %q", later, problem)
	}
}
