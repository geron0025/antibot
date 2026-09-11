package proxy

import (
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/headersfp"
	"github.com/geron0025/antibot/internal/hostnorm"
)

// EventLog is where the handler puts its events. An interface rather
// than a type: the hot path must not know that the log writes to files.
type EventLog interface {
	Write(facts.Request)
}

// Decider renders a decision from the signals. internal/rules implements
// it; the handler knows nothing about rules.
type Decider interface {
	Decide(*facts.Request) Decision
}

// Facts fills in what the fact set knows about the request: the network
// class and owner, the client family, whether the claimed client agrees
// with the handshake. internal/catalog implements it.
//
// It is deliberately unable to influence the decision: it is called
// before the decider and can only write into the signals. A fact set
// changes what a client is called, never what happens to it.
type Facts interface {
	Apply(*facts.Request)
}

// The actions a decider can return.
const (
	// ActionPass means no rule fired.
	ActionPass = "pass"

	// ActionAllow means an allowing rule fired. It differs from
	// ActionPass on purpose: the event must show that the request passed
	// by an exception rather than because nothing was found for it.
	ActionAllow = "allow"

	ActionBlock = "block"

	// ActionRatelimit means the rate limit was exceeded. Separate from
	// ActionBlock, because it is a different answer and a different
	// analysis: the client is not forbidden, it is too frequent.
	ActionRatelimit = "ratelimit"
)

// Decision is what to do with the request.
type Decision struct {
	Action string
	Rule   string
	Status int
	Body   string
}

// Pass is the default decision.
func Pass() Decision { return Decision{Action: ActionPass} }

// Handler is the hot path of a single request.
type Handler struct {
	Routes         *RouteTable
	Events         EventLog
	Decider        Decider
	Facts          Facts
	TrustedProxies []netip.Prefix
	OwnNetworks    []netip.Prefix
	Log            *slog.Logger

	// An ordinary map here would be a race: requests are served each in
	// its own goroutine, and the first two requests to a new upstream
	// would write into it at the same time.
	proxies sync.Map
}

// New takes the handler by pointer rather than by value: a struct with a
// sync.Map inside must not be copied.
func New(h *Handler) *Handler {
	if h.Log == nil {
		h.Log = slog.Default()
	}
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	req := h.collect(r, start)

	// The facts are applied before the rules and after everything taken
	// off the wire: a rule may refer to them, and an event has to be able
	// to explain the decision afterwards.
	if h.Facts != nil {
		h.Facts.Apply(&req)
	}

	decision := Pass()

	// Own networks are checked before the rules and separately from them.
	// This is not a rule of the highest priority: one's own monitoring
	// caught by a block is discovered late and always at the wrong time.
	addr, _ := netip.ParseAddr(req.IP)
	own := InOwnNetworks(addr, h.OwnNetworks)

	if !own && h.Decider != nil {
		decision = h.Decider.Decide(&req)
	}
	if own {
		decision.Rule = "own network"
	}

	req.Decision = decision.Action
	req.Rule = decision.Rule

	switch decision.Action {
	case ActionBlock, ActionRatelimit:
		status := decision.Status
		if status == 0 {
			status = http.StatusForbidden
			if decision.Action == ActionRatelimit {
				status = http.StatusTooManyRequests
			}
		}
		req.Status = status
		http.Error(w, bodyOrDefault(decision.Body, decision.Action), status)
	default:
		h.forward(w, r, &req)
	}

	req.Duration = time.Since(start)
	if h.Events != nil {
		h.Events.Write(req)
	}
}

func bodyOrDefault(body, action string) string {
	if body != "" {
		return body
	}
	if action == ActionRatelimit {
		return "Too many requests"
	}
	return "Access denied"
}

// collect gathers everything known about the request.
func (h *Handler) collect(r *http.Request, start time.Time) facts.Request {
	req := facts.Request{
		Time:    start,
		Host:    hostnorm.Normalize(r.Host),
		Method:  r.Method,
		Path:    r.URL.Path,
		Proto:   r.Proto,
		UA:      r.UserAgent(),
		Referer: r.Referer(),

		// Until a fact set says otherwise there are no grounds to claim
		// the client is lying about itself. The default is true and not
		// the zero value on purpose: a rule is written as "block those
		// whose ua_matches_ja4 is false", and with a false default such a
		// rule would block every visitor on a node that has no facts.
		UAMatchesJA4: true,
	}

	if addr := ClientAddr(r, h.TrustedProxies); addr.IsValid() {
		req.IP = addr.String()
	}

	if info := ConnInfoFrom(r.Context()); info != nil {
		if info.Hello != nil {
			req.JA3 = info.Hello.JA3()
			req.JA3Hash = info.Hello.JA3Hash()
			req.JA4 = info.Hello.JA4()
			req.SNI = info.Hello.SNI
			req.GREASE = info.Hello.HasGREASE
			if len(info.Hello.ALPN) > 0 {
				req.ALPN = strings.Join(info.Hello.ALPN, ",")
			}
		}
		if info.Sniffer != nil {
			req.H2 = info.Sniffer.Fingerprint().String()
		}
		if info.State != nil {
			req.TLSVersion = tlsVersion(info.State.Version)
		}
	}

	if req.TLSVersion == "" && r.TLS != nil {
		req.TLSVersion = tlsVersion(r.TLS.Version)
	}

	// In HTTP/2 the header order is known exactly, in HTTP/1.1 it is not.
	// The fingerprint is assembled from what there is, and that is more
	// honest than pretending the order is always known.
	fp := headersfp.FromHTTP1Request(r)
	req.Headers, req.HeadersHash = fp.Names, fp.Hash

	return req
}

func tlsVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	case 0x0302:
		return "1.1"
	case 0x0301:
		return "1.0"
	default:
		return ""
	}
}

func (h *Handler) forward(w http.ResponseWriter, r *http.Request, req *facts.Request) {
	to, ok := h.Routes.To(r.Host)
	if !ok {
		req.Status = http.StatusNotFound
		http.Error(w, "Domain not served", http.StatusNotFound)
		return
	}

	proxy, err := h.proxyFor(to)
	if err != nil {
		h.Log.Error("invalid upstream address", "address", to, "err", err)
		req.Status = http.StatusBadGateway
		http.Error(w, "The site is temporarily unavailable", http.StatusBadGateway)
		return
	}

	counter := &responseCounter{ResponseWriter: w, status: http.StatusOK}
	proxy.ServeHTTP(counter, r)
	req.Status, req.Bytes = counter.status, counter.bytes
}

func (h *Handler) proxyFor(to string) (*httputil.ReverseProxy, error) {
	if p, ok := h.proxies.Load(to); ok {
		return p.(*httputil.ReverseProxy), nil
	}
	u, err := url.Parse(to)
	if err != nil {
		return nil, err
	}
	p := httputil.NewSingleHostReverseProxy(u)
	p.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		h.Log.Warn("the upstream did not answer", "address", to, "err", err)
		http.Error(w, "The site is temporarily unavailable", http.StatusBadGateway)
	}
	// A race between the first two requests is harmless: one instance
	// wins and the loser is collected by the garbage collector.
	actual, _ := h.proxies.LoadOrStore(to, p)
	return actual.(*httputil.ReverseProxy), nil
}

// responseCounter remembers the status and the volume — they have to be
// written into the event, and http.ResponseWriter does not keep them.
type responseCounter struct {
	http.ResponseWriter
	status  int
	bytes   int64
	written bool
}

func (c *responseCounter) WriteHeader(status int) {
	if !c.written {
		c.status, c.written = status, true
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *responseCounter) Write(b []byte) (int, error) {
	c.written = true
	n, err := c.ResponseWriter.Write(b)
	c.bytes += int64(n)
	return n, err
}

// Flush is mandatory: without it the wrapper silently breaks everything
// served as a stream — server-sent events, long downloads, responses
// without a length. A ResponseWriter wrapper that does not pass Flush
// through is a classic of this kind of mistake.
func (c *responseCounter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
