package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/summary"
)

// The node's API: the numbers the admin UI shows, for a program rather
// than a human. It lives on the admin UI's address, under /api/v1/, with
// the admin UI's rules — loopback by default, outward only with a
// certificate. There is no second listener with rules of its own.
//
// A program comes with a token, never with a session. The HTML forms do
// not take a token and the API does not take a session cookie: neither
// door opens the other, and a request that carries no cookie leaves CSRF
// nothing to forge.

const (
	// A token is 256 random bits and is not guessed; the bound is there
	// so that a stream of refused requests does not fill the node's log.
	apiRefusedLimit  = 20
	apiRefusedWindow = 5 * time.Minute

	apiMaxRows       = 1000
	apiDefaultEvents = 100
	apiMaxPeriod     = 90 * 24 * time.Hour
)

func (s *Server) apiRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/summary", s.requireToken(ScopeRead, s.apiSummary))
	mux.Handle("GET /api/v1/events", s.requireToken(ScopeRead, s.apiEvents))
	mux.Handle("GET /api/v1/rules", s.requireToken(ScopeRead, s.apiRules))

	// Anything else under /api/ answers in JSON: a program that got the
	// address wrong must not receive the login page a browser would.
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		apiFail(w, http.StatusNotFound, "no such API address: "+r.Method+" "+r.URL.Path)
	})
}

// requireToken closes an API address behind a token of the given scope.
func (s *Server) requireToken(scope string, next func(http.ResponseWriter, *http.Request, *Token)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		value = strings.TrimSpace(value)
		if !ok || value == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="antibot"`)
			apiFail(w, http.StatusUnauthorized, "an API token is needed: Authorization: Bearer <token>")
			return
		}

		now := time.Now()
		tok, err := s.o.Tokens.Check(value, now)
		if err != nil {
			refused := errors.Is(err, ErrTokenUnknown) || errors.Is(err, ErrTokenRevoked) ||
				errors.Is(err, ErrTokenExpired)
			if !refused {
				s.o.Log.Error("the API tokens were not read", "err", err)
				apiFail(w, http.StatusServiceUnavailable, "the node could not read its API tokens")
				return
			}
			// Only refusals are counted: a working token must not run into
			// the limit of a monitoring system asking every minute.
			if s.o.Attempts != nil &&
				s.o.Attempts.Exceeded("api:"+clientAddr(r), apiRefusedLimit, apiRefusedWindow, now) {
				apiFail(w, http.StatusTooManyRequests, "too many refused tokens from this address; wait")
				return
			}
			s.o.Log.Warn("an API token was refused", "reason", err, "address", clientAddr(r))
			w.Header().Set("WWW-Authenticate", `Bearer realm="antibot", error="invalid_token"`)
			apiFail(w, http.StatusUnauthorized, err.Error())
			return
		}

		if !tok.Allows(scope) {
			apiFail(w, http.StatusForbidden, "the token "+tok.Name+" may only read")
			return
		}
		next(w, r, tok)
	})
}

// --- reading ---

type apiSummaryAnswer struct {
	From    time.Time        `json:"from"`
	To      time.Time        `json:"to"`
	Summary *summary.Summary `json:"summary"`
}

// apiSummary is the overview page as numbers: the same summary.Build, so
// the API and the admin UI cannot disagree.
func (s *Server) apiSummary(w http.ResponseWriter, r *http.Request, _ *Token) {
	period, err := apiPeriod(r)
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}
	top, err := apiInt(r, "top", 10, 1, apiMaxRows)
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now()
	result, err := summary.Build(summary.Options{
		Dir: s.o.EventsDir, From: now.Add(-period), To: now,
		Top: top, Buckets: bucketsFor(period),
	})
	if err != nil {
		s.apiInternal(w, "the API summary was not built", err)
		return
	}
	apiRespond(w, http.StatusOK, apiSummaryAnswer{
		From: now.Add(-period).UTC(), To: now.UTC(), Summary: result,
	})
}

type apiEventsAnswer struct {
	Events []facts.Request `json:"events"`

	// NextBefore is where the next page starts; absent on the last one.
	NextBefore string `json:"next_before,omitempty"`
}

// apiEvents is the events page: the same filters, newest first, page by
// page back in time.
func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request, _ *Token) {
	q := r.URL.Query()
	f := summary.Filter{
		Host: q.Get("host"), Decision: q.Get("decision"), Rule: q.Get("rule"),
		IP: q.Get("ip"), JA4: q.Get("ja4"), Search: q.Get("q"), Status: q.Get("status"),
	}
	if before := q.Get("before"); before != "" {
		t, err := time.Parse(time.RFC3339Nano, before)
		if err != nil {
			apiFail(w, http.StatusBadRequest,
				fmt.Sprintf("before %q: a moment like 2026-09-13T12:00:00Z, as next_before gives it", before))
			return
		}
		f.Before = t
	}
	limit, err := apiInt(r, "limit", apiDefaultEvents, 1, apiMaxRows)
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}

	list, err := summary.Latest(s.o.EventsDir, f, limit)
	if err != nil {
		s.apiInternal(w, "the API events were not read", err)
		return
	}
	answer := apiEventsAnswer{Events: list}
	if answer.Events == nil {
		answer.Events = []facts.Request{}
	}
	// A full page may have more behind it; the next one starts before the
	// oldest event of this one. Two events stamped with the very same
	// nanosecond across the boundary are the price of a cursor that keeps
	// no state on the node.
	if len(list) == limit {
		answer.NextBefore = list[len(list)-1].Time.UTC().Format(time.RFC3339Nano)
	}
	apiRespond(w, http.StatusOK, answer)
}

type apiRulesAnswer struct {
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Events int       `json:"events"`
	Rules  []RuleRow `json:"rules"`
}

// apiRules is the rules page: the order of application, and how often
// each rule fired over the period.
func (s *Server) apiRules(w http.ResponseWriter, r *http.Request, _ *Token) {
	period, err := apiPeriod(r)
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now()
	rows, events, err := s.ruleRows(now, period)
	if err != nil {
		// The page can show the rules without their counts and say so;
		// an answer with zeros where the counts should be would be read
		// by a program as "fired zero times".
		s.apiInternal(w, "the API rule counts were not read", err)
		return
	}
	if rows == nil {
		rows = []RuleRow{}
	}
	apiRespond(w, http.StatusOK, apiRulesAnswer{
		From: now.Add(-period).UTC(), To: now.UTC(), Events: events, Rules: rows,
	})
}

// --- helpers ---

// apiPeriod reads ?period=24h. Unlike the pages, a period the API cannot
// read is a 400 rather than the default: a program must learn that it
// asked for something else than it got.
func apiPeriod(r *http.Request) (time.Duration, error) {
	raw := r.URL.Query().Get("period")
	if raw == "" {
		return 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 || d > apiMaxPeriod {
		return 0, fmt.Errorf("period %q: a duration like 24h, up to %s", raw, apiMaxPeriod)
	}
	return d, nil
}

func apiInt(r *http.Request, name string, byDefault, least, most int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return byDefault, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < least || n > most {
		return 0, fmt.Errorf("%s %q: a number from %d to %d", name, raw, least, most)
	}
	return n, nil
}

func (s *Server) apiInternal(w http.ResponseWriter, what string, err error) {
	s.o.Log.Error(what, "err", err)
	apiFail(w, http.StatusInternalServerError, err.Error())
}

func apiRespond(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(body)
}

func apiFail(w http.ResponseWriter, code int, text string) {
	apiRespond(w, code, map[string]string{"error": text})
}
