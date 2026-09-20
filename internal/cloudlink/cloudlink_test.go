package cloudlink

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/schemacheck"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "cloud.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A node nobody has answered for is the normal state of a fresh
// installation, not a fault.
func TestAMissingFileIsAnUnansweredNode(t *testing.T) {
	s := tempStore(t)
	if st := s.State(); st.Answered || st.Token != "" {
		t.Fatalf("out of nowhere: %+v", st)
	}
}

// The answer survives a restart, and saying no to both is an answer:
// otherwise the node would ask again at every login until the owner
// said yes to something.
func TestNoToBothIsStillAnAnswer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Answer(false, false, time.Now()); err != nil {
		t.Fatal(err)
	}

	again, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := again.State()
	if !st.Answered || st.Facts || st.Aggregates {
		t.Fatalf("%+v", st)
	}
}

// The token opens the bases and names the installation. Nobody but the
// node's own user has business reading it.
func TestTheFileWithTheTokenIsReadableByItsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cloud.json")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Keep(Answer{Token: "ab_secret", Tenant: "node-1",
		FactsURL: "https://c/facts", IngestURL: "https://c/ingest"}, time.Now()); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("mode %o", mode)
	}
	if s.State().Token != "ab_secret" {
		t.Errorf("token: %+v", s.State())
	}
}

// Forgetting is for the owner who wants the node to stop talking to the
// cloud entirely: the checkboxes go down with the token, or the next
// start would quietly resume.
func TestForgettingDropsTheTokenAndTheAnswers(t *testing.T) {
	s := tempStore(t)
	if err := s.Answer(true, true, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Keep(Answer{Token: "ab_secret", FactsURL: "u", IngestURL: "u"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(); err != nil {
		t.Fatal(err)
	}

	st := s.State()
	if st.Token != "" || st.Facts || st.Aggregates || st.FactsURL != "" {
		t.Fatalf("%+v", st)
	}
	if !st.Answered {
		t.Error("forgetting unasked the owner")
	}
}

// The supervisor starts and stops the fetching by this: a change nobody
// is told about applies at the next start, which is what this whole
// package exists to avoid.
func TestAChangeIsAnnounced(t *testing.T) {
	s := tempStore(t)
	var told int
	s.OnChange(func() { told++ })

	if err := s.Answer(true, false, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Keep(Answer{Token: "t", FactsURL: "u", IngestURL: "u"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if told != 2 {
		t.Fatalf("told %d times", told)
	}
}

// What goes out is the protocol's document and nothing besides. The
// schema is the judge here as on the other side.
func TestWhatIsSentIsWhatTheSchemaSays(t *testing.T) {
	schema, err := schemacheck.Load(filepath.Join("..", "..", "docs", "schema",
		"registration.schema.json"))
	if err != nil {
		t.Fatal(err)
	}

	var sent any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &sent)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"format":1,"token":"ab_v","scope":"both","level":"node",
			"tenant":"node-1","facts_url":"https://c/facts","ingest_url":"https://c/ingest"}`)
	}))
	defer srv.Close()

	a, err := Register(context.Background(), srv.URL, "01JB8Z0K", "v0.6.0", true, false, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if a.Token != "ab_v" || a.FactsURL != "https://c/facts" || a.IngestURL != "https://c/ingest" {
		t.Fatalf("%+v", a)
	}
	if errs := schemacheck.Validate(schema, sent); len(errs) > 0 {
		t.Errorf("what we send does not fit the schema: %v", errs)
	}
}

// The three refusals the node acts on differently: one needs a human,
// one needs waiting, one needs reading.
func TestTheRefusalsAreToldApart(t *testing.T) {
	cases := []struct {
		status int
		header string
		body   string
		check  func(*testing.T, error)
	}{
		{http.StatusConflict, "", `{"error":"already"}`, func(t *testing.T, err error) {
			if !errors.Is(err, ErrAlreadyRegistered) {
				t.Errorf("409: %v", err)
			}
		}},
		{http.StatusTooManyRequests, "60", `{"error":"too many"}`, func(t *testing.T, err error) {
			var soon *TooSoon
			if !errors.As(err, &soon) || soon.RetryAfter != time.Minute {
				t.Errorf("429: %v", err)
			}
		}},
		{http.StatusBadRequest, "", `{"error":"format is not 1"}`, func(t *testing.T, err error) {
			var refused *Refused
			if !errors.As(err, &refused) || refused.Text != "format is not 1" {
				t.Errorf("400: %v", err)
			}
		}},
	}

	for _, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c.header != "" {
				w.Header().Set("Retry-After", c.header)
			}
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		}))
		_, err := Register(context.Background(), srv.URL, "n", "v0.6.0", true, true, srv.Client())
		c.check(t, err)
		srv.Close()
	}
}

// An answer with a field we do not know is not ours: reading it as ours
// would hide the day the two sides stop agreeing.
func TestAnAnswerIsReadStrictly(t *testing.T) {
	for _, body := range []string{
		`{"format":1,"token":"t","scope":"both","level":"node","tenant":"n",
			"facts_url":"u","ingest_url":"u","surprise":true}`,
		`{"format":2,"token":"t","scope":"both","level":"node","tenant":"n",
			"facts_url":"u","ingest_url":"u"}`,
		`{"format":1,"token":"","scope":"both","level":"node","tenant":"n",
			"facts_url":"u","ingest_url":"u"}`,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, body)
		}))
		if _, err := Register(context.Background(), srv.URL, "n", "v", true, true, srv.Client()); err == nil {
			t.Errorf("%s was taken", body)
		}
		srv.Close()
	}
}
