package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/i18n"
	"github.com/geron0025/antibot/internal/replay"
	"github.com/geron0025/antibot/internal/rules"
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

	// A rule with long lists is kilobytes; a megabyte is room to spare
	// and not a way to fill the node's memory.
	apiBodyLimit = 1 << 20

	apiDefaultExamples = 5
	apiMaxExamples     = 50
)

func (s *Server) apiRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/summary", s.requireToken(ScopeRead, s.apiSummary))
	mux.Handle("GET /api/v1/events", s.requireToken(ScopeRead, s.apiEvents))
	mux.Handle("GET /api/v1/rules", s.requireToken(ScopeRead, s.apiRules))
	mux.Handle("GET /api/v1/alerts", s.requireToken(ScopeRead, s.apiAlerts))
	mux.Handle("GET /api/v1/proposals", s.requireToken(ScopeRead, s.apiProposals))

	// A replay writes nothing, so reading is enough for it: a monitoring
	// system may ask whom a draft would touch without being able to put
	// the draft to work.
	mux.Handle("POST /api/v1/replay", s.requireToken(ScopeRead, s.apiReplay))

	// The writes, all of them. The same rules.Store methods as `antibot
	// rules` — the same checks, the same atomic replacement — and every
	// change lands in the node's log with the token's name.
	mux.Handle("POST /api/v1/rules", s.requireToken(ScopeWrite, s.apiAddRule))
	mux.Handle("POST /api/v1/rules/{id}/enable", s.requireToken(ScopeWrite, s.apiToggleRule(true)))
	mux.Handle("POST /api/v1/rules/{id}/disable", s.requireToken(ScopeWrite, s.apiToggleRule(false)))
	mux.Handle("POST /api/v1/rules/{id}/mode", s.requireToken(ScopeWrite, s.apiSetRuleMode))
	mux.Handle("DELETE /api/v1/rules/{id}", s.requireToken(ScopeWrite, s.apiRemoveRule))
	mux.Handle("POST /api/v1/proposals/{id}/accept", s.requireToken(ScopeWrite, s.apiAcceptProposal))
	mux.Handle("POST /api/v1/proposals/{id}/reject", s.requireToken(ScopeWrite, s.apiRejectProposal))

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
	f := eventsFilter(q)
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

// --- alerts ---

type apiAlertFiring struct {
	ID       string    `json:"id"`
	Text     string    `json:"text"`
	Since    time.Time `json:"since"`
	Clearing bool      `json:"clearing"`
}

type apiAlertTrigger struct {
	Kind   string           `json:"kind"`
	Title  string           `json:"title"`
	When   string           `json:"when"`
	Firing []apiAlertFiring `json:"firing"`
}

// apiAlertMessage is a message as the API has always given it: in
// English, whatever the language of the delivery.
type apiAlertMessage struct {
	ID       string    `json:"id"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"`
	Text     string    `json:"text"`
	Host     string    `json:"host"`
	Time     time.Time `json:"time"`
	Delivery string    `json:"delivery"`
}

// englishText is a message of the core in English; a core that sends no
// key gives its own words.
func englishText(text string, m alerts.Message) string {
	if m.Key == "" {
		return text
	}
	return m.In(i18n.EN)
}

type apiAlertsAnswer struct {
	Triggers []apiAlertTrigger `json:"triggers"`
	History  []apiAlertMessage `json:"history"`
}

// apiAlerts is the alerts page for a program: every trigger with its
// thresholds and what fires now, and the messages since the start with
// what became of each delivery. A monitoring system that asks this does
// not need the node's command at all.
func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request, _ *Token) {
	state, err := s.coreAlerts(r.Context())
	if err != nil {
		apiFail(w, http.StatusServiceUnavailable, "the core does not answer")
		return
	}
	if !state.Enabled {
		apiFail(w, http.StatusNotFound, "the alerts are off: alerts.enabled is false")
		return
	}
	firing := state.Firing
	answer := apiAlertsAnswer{Triggers: []apiAlertTrigger{}, History: []apiAlertMessage{}}
	for _, t := range state.Triggers {
		trigger := apiAlertTrigger{Kind: t.Kind, Title: t.Title, When: t.When, Firing: []apiAlertFiring{}}
		for _, f := range firing {
			if f.Kind == t.Kind {
				trigger.Firing = append(trigger.Firing, apiAlertFiring{
					ID: f.ID, Text: englishText(f.Text, f.Message), Since: f.Since.UTC(), Clearing: f.Clearing})
			}
		}
		answer.Triggers = append(answer.Triggers, trigger)
	}
	for _, e := range state.History {
		answer.History = append(answer.History, apiAlertMessage{
			ID: e.ID, Kind: e.Kind, State: e.State, Text: englishText(e.Text, e.Message),
			Host: e.Host, Time: e.Time.UTC(), Delivery: e.Delivery})
	}
	apiRespond(w, http.StatusOK, answer)
}

// --- replaying a draft ---

type apiReplayRequest struct {
	Rule     *rules.Rule `json:"rule"`
	Period   string      `json:"period"`
	Examples *int        `json:"examples"`
}

type apiReplayRule struct {
	ID      string          `json:"id"`
	Mode    string          `json:"mode"`
	Action  string          `json:"action"`
	Matched int             `json:"matched"`
	IPs     int             `json:"ips"`
	Hosts   int             `json:"hosts"`
	UAs     int             `json:"uas"`
	Share   float64         `json:"share"`
	Samples []facts.Request `json:"samples"`
}

type apiReplayAnswer struct {
	From        time.Time      `json:"from"`
	To          time.Time      `json:"to"`
	Events      int            `json:"events"`
	IPs         int            `json:"ips"`
	Decisions   map[string]int `json:"decisions"`
	Divergences map[string]int `json:"divergences"`
	Rule        apiReplayRule  `json:"rule"`
}

// apiReplay runs a draft over the log together with the rules in force —
// a draft with the id of a rule in force takes its place — and answers
// whom it would touch. Nothing is written: this is `antibot replay` for
// one rule, with the same engine and a limiter of its own.
func (s *Server) apiReplay(w http.ResponseWriter, r *http.Request, _ *Token) {
	if s.o.Rules == nil {
		apiFail(w, http.StatusNotFound, "the rules are not connected")
		return
	}
	var req apiReplayRequest
	if code, err := readBody(w, r, &req); err != nil {
		apiFail(w, code, err.Error())
		return
	}
	if req.Rule == nil {
		apiFail(w, http.StatusBadRequest, `a draft is needed: {"rule": {…}}`)
		return
	}
	period, err := parsePeriod(req.Period)
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}
	examples := apiDefaultExamples
	if req.Examples != nil {
		examples = *req.Examples
		if examples < 0 || examples > apiMaxExamples {
			apiFail(w, http.StatusBadRequest, fmt.Sprintf("examples: from 0 to %d", apiMaxExamples))
			return
		}
	}

	draft := *req.Rule
	var list []rules.Rule
	for _, rule := range s.o.Rules.Set().All() {
		if rule.ID != draft.ID {
			list = append(list, rule)
		}
	}
	set, err := rules.Build(append(list, draft), rules.NewWindows())
	if err != nil {
		apiFail(w, http.StatusBadRequest, err.Error())
		return
	}

	now := time.Now()
	result, err := replay.Run(replay.Options{
		Dir: s.o.EventsDir, From: now.Add(-period), To: now, Samples: examples,
	}, set)
	if err != nil {
		s.apiInternal(w, "the API replay did not run", err)
		return
	}

	answer := apiReplayAnswer{
		From: now.Add(-period).UTC(), To: now.UTC(), Events: result.Events, IPs: result.IPs,
		Decisions: result.Decisions, Divergences: result.Divergences,
		Rule: apiReplayRule{ID: draft.ID, Mode: draft.Mode, Action: draft.Action.Type,
			Share: result.Share(draft.ID), Samples: []facts.Request{}},
	}
	if stats, ok := result.Rules[draft.ID]; ok {
		answer.Rule.Matched, answer.Rule.IPs = stats.Matched, stats.IPs
		answer.Rule.Hosts, answer.Rule.UAs = stats.Hosts, stats.UAs
		if stats.Samples != nil {
			answer.Rule.Samples = stats.Samples
		}
	}
	apiRespond(w, http.StatusOK, answer)
}

// --- writing ---

type apiRuleAnswer struct {
	Rule    rules.Rule `json:"rule"`
	Warning string     `json:"warning,omitempty"`
}

// apiAddRule adds a ready rule, like `antibot rules add`: checked on its
// own and within the set, written atomically, in force at once.
func (s *Server) apiAddRule(w http.ResponseWriter, r *http.Request, tok *Token) {
	if s.o.Rules == nil {
		apiFail(w, http.StatusNotFound, "the rules are not connected")
		return
	}
	var rule rules.Rule
	if code, err := readBody(w, r, &rule); err != nil {
		apiFail(w, code, err.Error())
		return
	}
	if err := s.o.Rules.Add(rule); err != nil {
		s.apiRuleFail(w, r, "the rule was not added through the API", rule.ID, tok, err)
		return
	}
	s.reload(r.Context(), control.ReloadRules)

	warning := ""
	if rule.Mode == rules.Active {
		// Allowed, as with the command, and said out loud: a rule added
		// straight into active was never looked at in shadow.
		warning = "the rule went straight into active; a replay over history first would have shown whom it touches"
		s.o.Log.Warn("a rule was added straight into active through the API",
			"rule", rule.ID, "token", tok.Name, "address", clientAddr(r))
	} else {
		s.o.Log.Info("a rule was added through the API",
			"rule", rule.ID, "mode", rule.Mode, "token", tok.Name, "address", clientAddr(r))
	}
	s.apiRule(w, http.StatusCreated, rule.ID, warning)
}

func (s *Server) apiToggleRule(enable bool) func(http.ResponseWriter, *http.Request, *Token) {
	return func(w http.ResponseWriter, r *http.Request, tok *Token) {
		if s.o.Rules == nil {
			apiFail(w, http.StatusNotFound, "the rules are not connected")
			return
		}
		id := r.PathValue("id")
		if err := s.o.Rules.Toggle(id, enable); err != nil {
			s.apiRuleFail(w, r, "the rule was not toggled through the API", id, tok, err)
			return
		}
		s.reload(r.Context(), control.ReloadRules)
		s.o.Log.Info("a rule was toggled through the API",
			"rule", id, "enabled", enable, "token", tok.Name, "address", clientAddr(r))
		s.apiRule(w, http.StatusOK, id, "")
	}
}

// apiSetRuleMode puts a rule to work or back into shadow. A proposal from
// the cloud never takes this step; the owner's own program may.
func (s *Server) apiSetRuleMode(w http.ResponseWriter, r *http.Request, tok *Token) {
	if s.o.Rules == nil {
		apiFail(w, http.StatusNotFound, "the rules are not connected")
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	if code, err := readBody(w, r, &body); err != nil {
		apiFail(w, code, err.Error())
		return
	}
	id := r.PathValue("id")
	if err := s.o.Rules.SetMode(id, body.Mode); err != nil {
		s.apiRuleFail(w, r, "the rule's mode was not changed through the API", id, tok, err)
		return
	}
	s.reload(r.Context(), control.ReloadRules)
	s.o.Log.Info("a rule's mode was changed through the API",
		"rule", id, "mode", body.Mode, "token", tok.Name, "address", clientAddr(r))
	s.apiRule(w, http.StatusOK, id, "")
}

func (s *Server) apiRemoveRule(w http.ResponseWriter, r *http.Request, tok *Token) {
	if s.o.Rules == nil {
		apiFail(w, http.StatusNotFound, "the rules are not connected")
		return
	}
	id := r.PathValue("id")
	if err := s.o.Rules.Remove(id); err != nil {
		s.apiRuleFail(w, r, "the rule was not deleted through the API", id, tok, err)
		return
	}
	s.reload(r.Context(), control.ReloadRules)
	s.o.Log.Info("a rule was deleted through the API",
		"rule", id, "token", tok.Name, "address", clientAddr(r))
	w.WriteHeader(http.StatusNoContent)
}

// TODO(T10): the API of docs/*/protocol/proposals.md's third channel. Not
// implemented yet.

func (s *Server) apiProposals(w http.ResponseWriter, r *http.Request, _ *Token) {
	apiFail(w, http.StatusNotImplemented, "not implemented")
}

func (s *Server) apiAcceptProposal(w http.ResponseWriter, r *http.Request, tok *Token) {
	apiFail(w, http.StatusNotImplemented, "not implemented")
}

func (s *Server) apiRejectProposal(w http.ResponseWriter, r *http.Request, tok *Token) {
	apiFail(w, http.StatusNotImplemented, "not implemented")
}

// apiRule answers with the rule as it now is in force: a program that
// changed it sees the result, not its own request echoed back.
func (s *Server) apiRule(w http.ResponseWriter, code int, id, warning string) {
	for _, rule := range s.o.Rules.Set().All() {
		if rule.ID == id {
			apiRespond(w, code, apiRuleAnswer{Rule: rule, Warning: warning})
			return
		}
	}
	apiFail(w, http.StatusInternalServerError, "the rule was written and is not in force: "+id)
}

// apiRuleFail tells the caller's mistake from the node's trouble: the
// first is theirs to fix, the second goes to the node's log.
func (s *Server) apiRuleFail(w http.ResponseWriter, r *http.Request, what, id string, tok *Token, err error) {
	var invalid *rules.InvalidError
	var missing *rules.NoRuleError
	var exists *rules.RuleExistsError
	switch {
	case errors.As(err, &invalid):
		apiFail(w, http.StatusBadRequest, err.Error())
	case errors.As(err, &missing):
		apiFail(w, http.StatusNotFound, err.Error())
	case errors.As(err, &exists):
		apiFail(w, http.StatusConflict, err.Error())
	default:
		s.o.Log.Error(what, "rule", id, "token", tok.Name, "address", clientAddr(r), "err", err)
		apiFail(w, http.StatusInternalServerError, err.Error())
	}
}

// readBody decodes a JSON body strictly: a typo in a field name is an
// error rather than a silently dropped intention, as in rules.json itself.
func readBody(w http.ResponseWriter, r *http.Request, v any) (int, error) {
	r.Body = http.MaxBytesReader(w, r.Body, apiBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return http.StatusRequestEntityTooLarge, fmt.Errorf("the body is larger than %d bytes", apiBodyLimit)
		}
		return http.StatusBadRequest, fmt.Errorf("the body: %w", err)
	}
	if dec.More() {
		return http.StatusBadRequest, errors.New("the body holds more than one JSON value")
	}
	return 0, nil
}

// --- helpers ---

// apiPeriod reads ?period=24h. Unlike the pages, a period the API cannot
// read is a 400 rather than the default: a program must learn that it
// asked for something else than it got.
func apiPeriod(r *http.Request) (time.Duration, error) {
	return parsePeriod(r.URL.Query().Get("period"))
}

func parsePeriod(raw string) (time.Duration, error) {
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
