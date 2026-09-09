package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/geron0025/antibot/internal/facts"
)

type memoryLog struct {
	mu     sync.Mutex
	events []facts.Request
}

func (l *memoryLog) Write(r facts.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, r)
}

func (l *memoryLog) last(t *testing.T) facts.Request {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.events) == 0 {
		t.Fatal("no events were recorded")
	}
	return l.events[len(l.events)-1]
}

type stubDecider struct{ d Decision }

func (s stubDecider) Decide(*facts.Request) Decision { return s.d }

func testBench(t *testing.T, decider Decider, own []netip.Prefix) (*Handler, *memoryLog) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "the site's page")
	}))
	t.Cleanup(backend.Close)

	l := &memoryLog{}
	h := New(&Handler{
		Routes:      NewRouter(map[string]string{"shop.example.ru": backend.URL}),
		Events:      l,
		Decider:     decider,
		OwnNetworks: own,
	})
	return h, l
}

func requestTo(host string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+host+"/catalog", nil)
	r.Host = host
	r.RemoteAddr = "203.0.113.5:1234"
	r.Header.Set("User-Agent", "Mozilla/5.0")
	return r
}

func TestARequestGoesThroughAndIsRecorded(t *testing.T) {
	h, l := testBench(t, nil, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestTo("shop.example.ru"))

	if w.Code != http.StatusOK {
		t.Fatalf("response code %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "the site's page") {
		t.Fatalf("response body: %q", w.Body.String())
	}

	e := l.last(t)
	if e.Host != "shop.example.ru" || e.Path != "/catalog" || e.IP != "203.0.113.5" {
		t.Errorf("the event lost signals: %+v", e)
	}
	if e.Decision != "pass" || e.Status != http.StatusOK {
		t.Errorf("decision %q, status %d", e.Decision, e.Status)
	}
	if e.Bytes == 0 {
		t.Error("the response volume was not counted")
	}
	if e.Duration <= 0 {
		t.Error("the duration was not measured")
	}
}

func TestABlockReturnsItsOwnCodeAndDoesNotReachTheUpstream(t *testing.T) {
	h, l := testBench(t, stubDecider{Decision{
		Action: "block", Rule: "hosting-without-a-browser",
		Status: http.StatusTooManyRequests, Body: "Not allowed",
	}}, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestTo("shop.example.ru"))

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("response code %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "the site's page") {
		t.Error("the request went to the upstream after all")
	}
	e := l.last(t)
	if e.Decision != "block" || e.Rule != "hosting-without-a-browser" {
		t.Errorf("event: decision %q, rule %q", e.Decision, e.Rule)
	}
}

// Own networks do not go through the rules at all. It is checked with a
// decider that forbids everything: if the request reached the site, the
// layer works.
func TestAnOwnNetworkBypassesTheRules(t *testing.T) {
	own := netip.MustParsePrefix("203.0.113.0/24")
	h, l := testBench(t, stubDecider{Decision{Action: "block"}}, []netip.Prefix{own})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestTo("shop.example.ru"))

	if w.Code != http.StatusOK {
		t.Fatalf("an own network was blocked: code %d", w.Code)
	}
	if e := l.last(t); e.Rule != "own network" {
		t.Errorf("the event does not show why it was let through: %q", e.Rule)
	}
}

func TestAnUnknownDomainIsNotProxied(t *testing.T) {
	h, l := testBench(t, nil, nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestTo("foreign.example.com"))

	if w.Code != http.StatusNotFound {
		t.Errorf("response code %d, want 404", w.Code)
	}
	if e := l.last(t); e.Status != http.StatusNotFound {
		t.Errorf("the event carries status %d", e.Status)
	}
}

// A ResponseWriter wrapper must pass Flush through, otherwise everything
// served as a stream breaks.
func TestTheCounterPassesFlushThrough(t *testing.T) {
	w := httptest.NewRecorder()
	c := &responseCounter{ResponseWriter: w, status: http.StatusOK}

	if _, ok := any(c).(http.Flusher); !ok {
		t.Fatal("the response counter cannot Flush")
	}
	c.Write([]byte("a part"))
	c.Flush()
	if !w.Flushed {
		t.Error("Flush did not reach the underlying ResponseWriter")
	}
}
