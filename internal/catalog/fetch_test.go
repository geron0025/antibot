package catalog

import (
	"compress/gzip"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// service is the update service as the protocol describes it: three
// addresses, a token on all of them, and answers the node has to handle.
type service struct {
	t        *testing.T
	signer   *signer
	manifest []byte
	set      []byte
	keys     []byte

	status   int // if non-zero, answered instead of everything else
	requests []*http.Request
}

func (s *service) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests = append(s.requests, r)

		if r.Header.Get("Authorization") != "Bearer the-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if s.status != 0 {
			w.WriteHeader(s.status)
			return
		}

		switch {
		case strings.HasPrefix(r.URL.Path, "/manifest"):
			var m Manifest
			if err := decodeInto(s.manifest, &m); err == nil {
				if r.Header.Get("If-None-Match") == `"`+strconv.Itoa(m.Version)+`"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			w.Write(s.manifest)

		case strings.HasPrefix(r.URL.Path, "/set/"):
			// Served gzipped, the way the protocol says.
			w.Header().Set("Content-Encoding", "gzip")
			zw := gzip.NewWriter(w)
			defer zw.Close()
			zw.Write(s.set)

		case r.URL.Path == "/keys":
			if s.keys == nil {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Write(s.keys)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func decodeInto(raw []byte, m *Manifest) error {
	parsed, err := ParseManifest(raw)
	if err != nil {
		return err
	}
	*m = *parsed
	return nil
}

func fetcherFor(t *testing.T, srv *service) (*Fetcher, *Store) {
	t.Helper()
	server := httptest.NewServer(srv.handler())
	t.Cleanup(server.Close)

	store := store(t, srv.signer)
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))

	f := NewFetcher(store, server.URL, "the-token", "8f14e45fceea167a5a36dedd4bea2543", "0.1.0", quiet)
	if f == nil {
		t.Fatal("the fetcher was not assembled")
	}
	return f, store
}

// The whole path end to end: manifest, set, five checks, applied.
func TestFetchesAndApplies(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, body := s.set(t, 137, []any{
		network("203.0.113.0/24", "hosting", 137, owner("Example Hosting Ltd")),
	}, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: body}

	f, store := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}

	if store.Current().Version() != 137 {
		t.Fatalf("version %d", store.Current().Version())
	}
	r := facts.Request{IP: "203.0.113.7"}
	store.Apply(&r)
	if r.NetClass != "hosting" || r.NetOwner != "Example Hosting Ltd" {
		t.Errorf("the set did not take effect: %+v", r)
	}
}

// The node says who it is, and nothing beyond that.
func TestTheNodeIntroducesItself(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, body := s.set(t, 137, nil, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: body}

	f, _ := fetcherFor(t, srv)
	f.Once(context.Background())

	var manifestReq *http.Request
	for _, r := range srv.requests {
		if strings.HasPrefix(r.URL.Path, "/manifest") {
			manifestReq = r
		}
	}
	if manifestReq == nil {
		t.Fatal("the manifest was not requested")
	}
	if got := manifestReq.Header.Get("X-Antibot-Node"); got != "8f14e45fceea167a5a36dedd4bea2543" {
		t.Errorf("node identifier: %q", got)
	}
	if got := manifestReq.Header.Get("X-Antibot-Version"); got != "0.1.0" {
		t.Errorf("node version: %q", got)
	}
	if got := manifestReq.URL.Query().Get("format"); got != "1" {
		t.Errorf("the format was not negotiated: %q", got)
	}
	// No domains, no addresses, no rules: distribution is not an excuse
	// to collect what is not in the aggregate.
	for _, name := range []string{"X-Antibot-Domains", "X-Antibot-Rules", "Cookie"} {
		if manifestReq.Header.Get(name) != "" {
			t.Errorf("the node sent %s", name)
		}
	}
}

// The same version is not downloaded twice: that is what If-None-Match
// is for.
func TestTheSameVersionIsNotDownloadedTwice(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, body := s.set(t, 137, nil, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: body}

	f, _ := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(srv.requests)

	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, r := range srv.requests[before:] {
		if strings.HasPrefix(r.URL.Path, "/set/") {
			t.Error("the set was downloaded again at the same version")
		}
	}
}

// A revoked token stops the updates and nothing else. The node keeps
// working on the set it already has: a revoked token is never a reason
// to stop protecting.
func TestARevokedTokenDoesNotLiftTheProtection(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, body := s.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: body}

	f, store := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv.status = http.StatusUnauthorized
	if err := f.Once(context.Background()); err == nil {
		t.Error("a refusal was not reported")
	}

	r := facts.Request{IP: "203.0.113.7"}
	store.Apply(&r)
	if r.NetClass != "hosting" {
		t.Error("the set stopped being applied after the token was refused")
	}
	if got := f.nextDelay(errSomething, time.Hour); got != retryAfterUnauthorized {
		t.Errorf("retry in %v, want %v", got, retryAfterUnauthorized)
	}
}

// A subscription that ran out freezes the base and leaves the
// protection. The opposite would mean an unpaid invoice opens somebody's
// site to bots.
func TestAnEndedSubscriptionFreezesTheBase(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, body := s.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: body}

	f, store := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err != nil {
		t.Fatal(err)
	}

	srv.status = http.StatusForbidden
	if err := f.Once(context.Background()); err == nil {
		t.Error("a refusal was not reported")
	}

	if store.Current().Version() != 137 {
		t.Error("the frozen base stopped being applied")
	}
	r := facts.Request{IP: "203.0.113.7"}
	store.Apply(&r)
	if r.NetClass != "hosting" {
		t.Error("the rules lost the facts after the subscription ended")
	}
	if got := f.nextDelay(errSomething, time.Hour); got != retryAfterForbidden {
		t.Errorf("retry in %v, want %v", got, retryAfterForbidden)
	}
}

var errSomething = errors.New("something")

// A cloud out of shape is retried with a growing delay, not every minute
// from every installation at once.
//
// One cycle makes several requests — keys, manifest, set — and counts as
// **one** failure. Counting each request would double the delay for a
// single outage, and that is exactly what the first version did.
func TestBackoffGrowsOncePerCycle(t *testing.T) {
	s := newSigner(t, "2026-a")
	srv := &service{t: t, signer: s, status: http.StatusInternalServerError}
	f, _ := fetcherFor(t, srv)

	const interval = 24 * time.Hour
	var delays []time.Duration
	for i := 0; i < 5; i++ {
		f.hint = 0
		err := f.Once(context.Background())
		if err == nil {
			t.Fatal("a failing service was reported as success")
		}
		delays = append(delays, f.nextDelay(err, interval))
	}

	if delays[0] != retryAfterFirstFailure {
		t.Errorf("the first delay is %v, want %v", delays[0], retryAfterFirstFailure)
	}
	for i := 1; i < len(delays); i++ {
		if delays[i] != delays[i-1]*2 {
			t.Fatalf("the delay did not double: %v", delays)
		}
	}
}

// The ceiling holds and the shift does not overflow on a node that has
// been offline for a year.
func TestBackoffHasACeiling(t *testing.T) {
	f := &Fetcher{}
	var delay time.Duration
	for i := 0; i < 1000; i++ {
		delay = f.nextDelay(errSomething, time.Hour)
		if delay <= 0 || delay > retryAfterMax {
			t.Fatalf("delay %v on attempt %d", delay, i)
		}
	}
	if delay != retryAfterMax {
		t.Errorf("the ceiling was not reached: %v", delay)
	}
}

// A cycle that worked returns to the ordinary schedule.
func TestSuccessReturnsToTheSchedule(t *testing.T) {
	f := &Fetcher{}
	f.nextDelay(errSomething, time.Hour)
	f.nextDelay(errSomething, time.Hour)
	if got := f.nextDelay(nil, time.Hour); got != time.Hour {
		t.Errorf("after a success the delay is %v", got)
	}
	if got := f.nextDelay(errSomething, time.Hour); got != retryAfterFirstFailure {
		t.Errorf("the counter was not reset: %v", got)
	}
}

// A forged set does not get applied even if the service serves it: the
// signature is checked against the node's own keyring, and the far side
// has no say in that.
func TestAForgedSetIsNotApplied(t *testing.T) {
	ours := newSigner(t, "2026-a")
	stranger := newSigner(t, "2026-x")

	manifest, body := stranger.set(t, 137, nil, nil)
	srv := &service{t: t, signer: ours, manifest: manifest, set: body}

	f, store := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err == nil {
		t.Fatal("a set signed by a stranger was applied")
	}
	if store.Current().Version() != 0 {
		t.Error("something got applied")
	}
}

// A set larger than the limit is not read into memory: the far side is
// reachable by anyone who got hold of the address.
func TestAnOversizedAnswerIsRefused(t *testing.T) {
	s := newSigner(t, "2026-a")
	manifest, _ := s.set(t, 137, nil, nil)
	srv := &service{t: t, signer: s, manifest: manifest, set: make([]byte, maxSetSize+1024)}

	f, _ := fetcherFor(t, srv)
	if err := f.Once(context.Background()); err == nil {
		t.Error("an oversized set was accepted")
	}
}

// Without a token there is no fetching at all — not "switched off by a
// setting" but no addressee.
func TestWithoutATokenThereIsNoFetcher(t *testing.T) {
	s := newSigner(t, "2026-a")
	store := store(t, s)

	if f := NewFetcher(store, "https://updates.example.com/facts", "", "id", "0.1.0", nil); f != nil {
		t.Error("a fetcher was assembled without a token")
	}
	if f := NewFetcher(store, "", "the-token", "id", "0.1.0", nil); f != nil {
		t.Error("a fetcher was assembled without an address")
	}
}
