package proposals

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/catalog"
)

// proposalsServer is a minimal stand-in for factory serve's
// GET /proposals?format=1.
type proposalsServer struct {
	body      []byte
	signature string
	etag      string

	// status, if not zero, is answered instead of everything else.
	status int

	requests        int
	lastIfNoneMatch string
}

func (s *proposalsServer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests++
		s.lastIfNoneMatch = r.Header.Get("If-None-Match")

		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}
		if s.etag != "" && r.Header.Get("If-None-Match") == s.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if s.signature != "" {
			w.Header().Set("X-Antibot-Signature", s.signature)
		}
		if s.etag != "" {
			w.Header().Set("ETag", s.etag)
		}
		w.Write(s.body)
	})
}

func newFetcher(t *testing.T, srv *proposalsServer, keyring *catalog.Keyring, served func(string) bool) (*Fetcher, string) {
	t.Helper()
	server := httptest.NewServer(srv.handler())
	t.Cleanup(server.Close)

	store, err := catalog.Open(t.TempDir(), true, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	src := catalog.NewFetcher(store, server.URL, "the-token", testNodeID, "0.1.0", quietLog())
	if src == nil {
		t.Fatal("the source fetcher was not assembled")
	}

	dir := t.TempDir()
	return &Fetcher{Source: src, Keyring: keyring, Dir: dir, Served: served, Log: quietLog()}, dir
}

func servedOnly(names ...string) func(string) bool {
	set := make(map[string]struct{}, len(names))
	for _, n := range names {
		set[n] = struct{}{}
	}
	return func(h string) bool { _, ok := set[h]; return ok }
}

func readProposalsFile(t *testing.T, dir string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func fileExists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, FileName))
	return err == nil
}

// The whole path end to end: a document signed by a trusted proposals
// key, addressed to this node, passing the schema, every id prefixed
// cloud-, every scope served, every rule compiling — is written whole.
func TestFetcherStoresAVerifiedDocument(t *testing.T) {
	signer := newTestSigner(t, "2026-p1")
	keyring, err := catalog.NewKeyringWithKeys(signer.key(catalog.UseProposals))
	if err != nil {
		t.Fatal(err)
	}

	body := marshal(t, goodDocument(testNodeID))
	srv := &proposalsServer{body: body, signature: signer.sign(body), etag: `"v1"`}
	f, dir := newFetcher(t, srv, keyring, servedOnly("shop.example.ru"))

	if err := f.Once(context.Background()); err != nil {
		t.Fatalf("a valid document was rejected: %v", err)
	}
	if got := readProposalsFile(t, dir); string(got) != string(body) {
		t.Error("the file does not hold the document exactly as it arrived")
	}
	if f.lastETag != `"v1"` {
		t.Errorf("the etag was not remembered: %q", f.lastETag)
	}
}

// Every one of the checks the protocol lists rejects the whole document
// and leaves the previous one exactly as it was.
func TestBadDocumentsLeaveThePreviousListInForce(t *testing.T) {
	goodSigner := newTestSigner(t, "2026-p1")
	factsSigner := newTestSigner(t, "2026-a")
	strangerSigner := newTestSigner(t, "2026-px")

	keyring, err := catalog.NewKeyringWithKeys(
		goodSigner.key(catalog.UseProposals),
		factsSigner.key(catalog.UseFacts),
	)
	if err != nil {
		t.Fatal(err)
	}
	served := servedOnly("shop.example.ru")

	goodBody := marshal(t, goodDocument(testNodeID))
	srv := &proposalsServer{body: goodBody, signature: goodSigner.sign(goodBody), etag: `"v1"`}
	f, dir := newFetcher(t, srv, keyring, served)
	if err := f.Once(context.Background()); err != nil {
		t.Fatalf("setup: a valid document was rejected: %v", err)
	}
	previous := readProposalsFile(t, dir)

	cases := []struct {
		name     string
		mutate   func(doc map[string]any)
		signWith *testSigner
	}{
		{"foreign key", func(map[string]any) {}, strangerSigner},
		{"facts-use key", func(map[string]any) {}, factsSigner},
		{"bad node", func(d map[string]any) {
			d["node"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, goodSigner},
		{"schema violation", func(d map[string]any) {
			delete(d, "created_at")
		}, goodSigner},
		{"id without cloud-", func(d map[string]any) {
			p := d["proposals"].([]any)[0].(map[string]any)
			p["id"] = "hosting-no-browser-2026-09"
			p["rule"].(map[string]any)["id"] = "hosting-no-browser-2026-09"
		}, goodSigner},
		{"scope of a domain not served", func(d map[string]any) {
			p := d["proposals"].([]any)[0].(map[string]any)
			p["rule"].(map[string]any)["scope"] = []any{"unrelated.example.com"}
		}, goodSigner},
		{"rule that does not compile", func(d map[string]any) {
			p := d["proposals"].([]any)[0].(map[string]any)
			cond := p["rule"].(map[string]any)["condition"].(map[string]any)
			cond["all"].([]any)[0].(map[string]any)["field"] = "no-such-field"
		}, goodSigner},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := deepCopy(t, goodDocument(testNodeID))
			tc.mutate(doc)
			body := marshal(t, doc)

			srv.body = body
			srv.signature = tc.signWith.sign(body)
			srv.etag = "" // force past If-None-Match; the body differs anyway

			if err := f.Once(context.Background()); err == nil {
				t.Fatal("a bad document was accepted")
			}
			if got := readProposalsFile(t, dir); string(got) != string(previous) {
				t.Error("the previous list was not preserved")
			}
		})
	}
}

// A 304 changes nothing and costs one request.
func TestFetcherNotModified(t *testing.T) {
	signer := newTestSigner(t, "2026-p1")
	keyring, err := catalog.NewKeyringWithKeys(signer.key(catalog.UseProposals))
	if err != nil {
		t.Fatal(err)
	}
	body := marshal(t, goodDocument(testNodeID))
	srv := &proposalsServer{body: body, signature: signer.sign(body), etag: `"v1"`}
	f, dir := newFetcher(t, srv, keyring, servedOnly("shop.example.ru"))

	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := srv.requests

	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	if srv.requests != before+1 {
		t.Fatalf("expected exactly one more request, got %d more", srv.requests-before)
	}
	if srv.lastIfNoneMatch != `"v1"` {
		t.Errorf("If-None-Match was not sent: %q", srv.lastIfNoneMatch)
	}
	if got := readProposalsFile(t, dir); string(got) != string(body) {
		t.Error("the file changed on a 304")
	}
}

// A revoked token keeps the previous list and retries in an hour.
func TestFetcherUnauthorized(t *testing.T) {
	signer := newTestSigner(t, "2026-p1")
	keyring, err := catalog.NewKeyringWithKeys(signer.key(catalog.UseProposals))
	if err != nil {
		t.Fatal(err)
	}
	srv := &proposalsServer{status: http.StatusUnauthorized}
	f, dir := newFetcher(t, srv, keyring, servedOnly("shop.example.ru"))

	if err := f.Once(context.Background()); err == nil {
		t.Fatal("a 401 was not reported")
	}
	if f.hint != retryAfterUnauthorized {
		t.Errorf("hint %v, want %v", f.hint, retryAfterUnauthorized)
	}
	if fileExists(dir) {
		t.Error("a file appeared from a 401")
	}
}

// A tier without facts_and_analysis keeps the previous list and retries
// about once a day — its own policy, apart from fact sets.
func TestFetcherForbidden(t *testing.T) {
	signer := newTestSigner(t, "2026-p1")
	keyring, err := catalog.NewKeyringWithKeys(signer.key(catalog.UseProposals))
	if err != nil {
		t.Fatal(err)
	}
	srv := &proposalsServer{status: http.StatusForbidden}
	f, dir := newFetcher(t, srv, keyring, servedOnly("shop.example.ru"))

	if err := f.Once(context.Background()); err == nil {
		t.Fatal("a 403 was not reported")
	}
	if f.hint != retryAfterForbidden {
		t.Errorf("hint %v, want %v", f.hint, retryAfterForbidden)
	}
	if fileExists(dir) {
		t.Error("a file appeared from a 403")
	}
}

// The backoff grows from a minute and doubles, the same shape as the
// fact set fetcher's — but through this Fetcher's own counter, proven
// apart in catalog's own tests (TestGetSignedLeavesTheFetchersStateAlone).
func TestFetcherBackoffGrows(t *testing.T) {
	f := &Fetcher{}
	someErr := errors.New("something")
	var delays []time.Duration
	for i := 0; i < 4; i++ {
		delays = append(delays, f.nextDelay(someErr, 24*time.Hour))
	}
	if delays[0] != retryAfterFirstFailure {
		t.Fatalf("first delay %v, want %v", delays[0], retryAfterFirstFailure)
	}
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[i-1]*2 {
			t.Fatalf("the delay did not double: %v", delays)
		}
	}
}

func TestFetcherSuccessResetsBackoff(t *testing.T) {
	f := &Fetcher{}
	someErr := errors.New("something")
	f.nextDelay(someErr, time.Hour)
	f.nextDelay(someErr, time.Hour)
	if got := f.nextDelay(nil, time.Hour); got != time.Hour {
		t.Errorf("after a success the delay is %v", got)
	}
	if got := f.nextDelay(someErr, time.Hour); got != retryAfterFirstFailure {
		t.Errorf("the counter was not reset: %v", got)
	}
}
