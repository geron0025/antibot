package admin

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/i18n"
	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/summary"
)

//go:embed templates/*.html templates/style.css
var templatesFS embed.FS

const (
	sessionCookieName = "antibot_session"
	csrfCookieName    = "antibot_csrf"
)

// parseTemplates parses the templates once per language: html/template
// takes its functions before parsing, and a template once executed can no
// longer be cloned, so a language cannot be swapped in per request.
func parseTemplates(catalog *i18n.Catalog) (map[i18n.Lang]*template.Template, error) {
	out := map[i18n.Lang]*template.Template{}
	for _, lang := range catalog.Langs() {
		t, err := template.New("").Funcs(templateFuncs(catalog.Printer(lang))).ParseFS(templatesFS, "templates/*.html")
		if err != nil {
			return nil, err
		}
		out[lang] = t
	}
	return out, nil
}

// sectionTitles name the sections for the menu and the page title.
var sectionTitles = map[string]string{
	"overview": "nav.overview",
	"events":   "nav.events",
	"rules":    "nav.rules",
	"domains":  "nav.domains",
	"alerts":   "nav.alerts",
	"settings": "nav.settings",
}

// alertStates and tokenStates name the states the core and the token
// file write as words of the code.
var (
	alertStates = map[string]string{
		alerts.Firing:   "alert_state.firing",
		alerts.Resolved: "alert_state.resolved",
		alerts.Test:     "alert_state.test",
	}
	tokenStates = map[string]string{
		TokenLive:    "token_state.live",
		TokenRevoked: "token_state.revoked",
		TokenExpired: "token_state.expired",
	}
)

// named is a word of the code as a human reads it; a word the table does
// not know is shown as the code wrote it.
func named(p *i18n.Printer, table map[string]string, word string) string {
	if key, ok := table[word]; ok {
		return p.T(key)
	}
	return word
}

func templateFuncs(p *i18n.Printer) template.FuncMap {
	return template.FuncMap{
		"t":        func(key string, args ...any) any { return localize(p, key, args...) },
		"tn":       func(key string, n int, args ...any) any { return localizeN(p, key, n, args...) },
		"lang":     func() string { return string(p.Lang()) },
		"share":    p.Percent,
		"time":     p.Time,
		"date":     p.Date,
		"count":    func(n int) string { return p.Number(int64(n)) },
		"bytes":    func(n int64) string { return formatBytes(p, n) },
		"latency":  func(d time.Duration) string { return formatLatency(p, d) },
		"truncate": truncate,
		"lower":    lower,
		"join":     strings.Join,
		"title": func(section string) string {
			if key, ok := sectionTitles[section]; ok {
				return p.T(key)
			}
			return p.T("nav.overview")
		},
		"alertState": func(state string) string { return named(p, alertStates, state) },
		"tokenState": func(state string) string { return named(p, tokenStates, state) },
		// breakdown assembles the data for one breakdown table: Go
		// templates have no other way to pass several values. key is the
		// events filter a row links to; extra is one more filter as a
		// name and a value, so that a path with 5xx opens exactly its 5xx.
		"breakdown": func(name any, key string, rows []summary.Row, extra ...string) map[string]any {
			data := map[string]any{"Name": name, "Key": key, "Rows": rows}
			if len(extra) == 2 {
				data["ExtraKey"], data["ExtraValue"] = extra[0], extra[1]
			}
			return data
		},
	}
}

// pageCommon is what every page carries.
type pageCommon struct {
	User    string
	Version string
	Section string
	Period  string
	Error   string

	// Back is where the language switch returns: this very page.
	Back string

	// Tab is the tab within the section, for the sections that have
	// them: settings.
	Tab string

	// APITokens shows the tokens page in the menu: without a tokens file
	// the API is off and the page has nothing to manage.
	APITokens bool

	// CoreDown says the core does not answer on its socket: the pages
	// show what lives in files, and nothing of what lives in its memory.
	CoreDown bool

	// Bell is what the bell in the header carries; nil without alerts.
	// The bell is also the way to the alerts page: the menu has no item
	// of its own for it.
	Bell *bellData
}

// bellData is the bell in the header of every page: what fires now and
// the latest messages. Two reads of memory and no disk, so it is cheap to
// build for every page — and a trigger firing while a human reads the
// rules must not wait for them to open the overview.
type bellData struct {
	Firing []alerts.Status
	Recent []alerts.Entry
}

// bellRecent is how many of the latest messages the bell lists; the rest
// are on the alerts page.
const bellRecent = 5

func bell(state control.Alerts) *bellData {
	recent := state.History
	if len(recent) > bellRecent {
		recent = recent[:bellRecent]
	}
	return &bellData{Firing: state.Firing, Recent: recent}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Language", string(s.lang(r)))
	if err := s.templates[s.lang(r)].ExecuteTemplate(w, name, data); err != nil {
		s.o.Log.Error("an admin UI page did not render", "template", name, "err", err)
	}
}

func (s *Server) style(w http.ResponseWriter, r *http.Request) {
	contents, err := templatesFS.ReadFile("templates/style.css")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(contents)
}

// --- login ---

type loginData struct {
	pageCommon
	CSRF string
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	// There is no point asking somebody who is already logged in.
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok := s.o.Sessions.Whose(cookie.Value, time.Now()); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}

	token, err := s.setCSRF(w, r)
	if err != nil {
		http.Error(w, s.t(r, "error.internal"), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "login.html", loginData{
		pageCommon: pageCommon{
			Version: s.o.Version,
			Error:   r.URL.Query().Get("error"),
			Back:    "/login",
		},
		CSRF: token,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}

	// Password guessing is limited by address rather than by name: the
	// name is guessed together with the password, and counting by name
	// would not notice such guessing.
	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		s.o.Log.Warn("too many admin UI login attempts", "address", clientAddr(r))
		http.Error(w, s.t(r, "error.too_many_attempts"), http.StatusTooManyRequests)
		return
	}

	name := r.PostFormValue("name")
	password := r.PostFormValue("password")

	if !s.o.Users.Check(name, password) {
		s.o.Log.Warn("a failed admin UI login", "name", name, "address", clientAddr(r))
		http.Redirect(w, r, "/login?error="+
			url.QueryEscape(s.t(r, "login.mismatch")), http.StatusSeeOther)
		return
	}

	key, until, err := s.o.Sessions.Start(name, now)
	if err != nil {
		http.Error(w, s.t(r, "error.internal"), http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    key,
		Path:     "/",
		Expires:  until,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	s.o.Log.Info("an admin UI login", "name", name, "address", clientAddr(r))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		s.o.Sessions.End(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- overview ---

type overviewData struct {
	pageCommon
	CSRF      string
	Summary   *summary.Summary
	Rules     int
	Effective int

	// ExpiringCerts is the 14-day warning: there is no auto-renewal, so
	// an expiring certificate is the owner's errand, and the overview is
	// where it must be impossible to miss.
	ExpiringCerts []CertState

	// Firing are the alerts firing now. The certificate alerts are left
	// out: the warning above already says the same in its own words.
	Firing []alerts.Status

	Cloud *CloudState

	ServerErrors int
	Answers      donutChart
	Series       *columnsChart
}

// expiringCerts lists the loaded certificates that run out within the
// warning window.
func (s *Server) expiringCerts(ctx context.Context, now time.Time) []CertState {
	var out []CertState
	for _, info := range s.coreCertificates(ctx) {
		if info.NotAfter.Sub(now) < expiryWarning {
			out = append(out, *certStateOf(info.Names, "", info.NotAfter, now))
		}
	}
	return out
}

func (s *Server) overviewPage(w http.ResponseWriter, r *http.Request, user string) {
	// The two questions about the cloud are asked once, at the first
	// login, and here rather than on a page nobody opens: what leaves
	// this node is the owner's decision, and a decision nobody was
	// offered is made by whoever wrote the defaults.
	cloud := s.coreCloud(r.Context())
	if cloud != nil && !cloud.FromConfig && !cloud.Answered {
		http.Redirect(w, r, "/settings/cloud?welcome=1", http.StatusSeeOther)
		return
	}

	period := periodOf(r)
	now := time.Now()

	result, err := summary.Build(summary.Options{
		Dir:     s.o.EventsDir,
		From:    now.Add(-period),
		To:      now,
		Buckets: bucketsFor(period),
	})
	if err != nil {
		// The log directory may not exist before the first event — that
		// is no reason to show an empty page without an explanation.
		s.render(w, r, "overview.html", overviewData{
			pageCommon: s.common(r, user, "overview", period, err.Error()),
			CSRF:       s.csrfToken(r),
			Summary:    &summary.Summary{Decisions: map[string]int{}},
		})
		return
	}

	data := overviewData{
		pageCommon:    s.common(r, user, "overview", period, ""),
		CSRF:          s.csrfToken(r),
		Summary:       result,
		ExpiringCerts: s.expiringCerts(r.Context(), now),
		ServerErrors:  result.Answers[summary.AnswerServerError],
		Answers:       newDonut(s.printer(r), result.Answers),
		Series:        newColumns(s.printer(r), result.Series, period),
	}
	if s.o.Rules != nil {
		set := s.o.Rules.Set()
		data.Rules = len(set.All())
		data.Effective = len(set.Effective())
	}
	if data.Bell != nil {
		for _, f := range data.Bell.Firing {
			if f.Kind != alerts.CertExpiring {
				data.Firing = append(data.Firing, f)
			}
		}
	}
	data.Cloud = cloud
	s.render(w, r, "overview.html", data)
}

// --- events ---

type eventsData struct {
	pageCommon
	CSRF   string
	Events []facts.Request
	Filter summary.Filter
	Limit  int

	// Export is the download of the same filters over the last day.
	Export string
}

// eventsFilter reads the events filters from a query: the page, its
// download and the API take the same ones.
func eventsFilter(q url.Values) summary.Filter {
	return summary.Filter{
		Host: q.Get("host"), Decision: q.Get("decision"), Rule: q.Get("rule"),
		IP: q.Get("ip"), JA4: q.Get("ja4"), Search: q.Get("q"), Status: q.Get("status"),
	}
}

func (s *Server) eventsPage(w http.ResponseWriter, r *http.Request, user string) {
	f := eventsFilter(r.URL.Query())
	export := url.Values{"period": {"24h"}}
	for key, value := range r.URL.Query() {
		if key != "period" && len(value) > 0 && value[0] != "" {
			export.Set(key, value[0])
		}
	}
	limit := 200

	list, err := summary.Latest(s.o.EventsDir, f, limit)
	message := ""
	if err != nil {
		message = err.Error()
	}

	s.render(w, r, "events.html", eventsData{
		pageCommon: s.common(r, user, "events", 0, message),
		CSRF:       s.csrfToken(r),
		Events:     list,
		Filter:     f,
		Limit:      limit,
		Export:     "/events/export?" + export.Encode(),
	})
}

// --- rules ---

// RuleRow is a rule together with how many times it fired over the
// period. The API answers with it as is.
type RuleRow struct {
	Rule    rules.Rule `json:"rule"`
	Matched int        `json:"matched"`
	IPs     int        `json:"ips"`
	Enabled bool       `json:"enabled"`
}

type rulesData struct {
	pageCommon
	CSRF   string
	Rules  []RuleRow
	Events int
}

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request, user string) {
	period := periodOf(r)
	data := rulesData{
		pageCommon: s.common(r, user, "rules", period, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
	}
	rows, events, err := s.ruleRows(time.Now(), period)
	data.Rules, data.Events = rows, events
	if err != nil {
		data.Error = err.Error()
	}
	s.render(w, r, "rules.html", data)
}

// ruleRows lists the rules in the order of application, the disabled
// after them, each with how often it fired over the period. The rules
// page and the API share it: two lists that could disagree about what
// fired would be worse than one.
//
// How often a rule fired comes from the log rather than from in-memory
// counters: after a restart the counters reset while the log stays. The
// rows come back even when the log could not be read; the error says the
// counts are missing.
func (s *Server) ruleRows(now time.Time, period time.Duration) ([]RuleRow, int, error) {
	if s.o.Rules == nil {
		return nil, 0, nil
	}

	fired := map[string]summary.Row{}
	events := 0
	result, err := summary.Build(summary.Options{
		Dir: s.o.EventsDir, From: now.Add(-period), To: now,
		Top: 1000,
	})
	if err == nil {
		events = result.Events
		for _, row := range result.Rules {
			fired[row.Value] = row
		}
		for _, row := range result.Shadows {
			fired[row.Value] = row
		}
	}

	set := s.o.Rules.Set()
	effective := map[string]struct{}{}
	for _, rule := range set.Effective() {
		effective[rule.ID] = struct{}{}
	}

	// The order of application rather than the order in the file: a human
	// looks here when working out why the wrong thing fired.
	var rows []RuleRow
	for _, rule := range set.Effective() {
		row := fired[rule.ID]
		rows = append(rows, RuleRow{Rule: rule, Matched: row.Count, IPs: row.IPs, Enabled: true})
	}
	for _, rule := range set.All() {
		if _, ok := effective[rule.ID]; ok {
			continue
		}
		row := fired[rule.ID]
		rows = append(rows, RuleRow{Rule: rule, Matched: row.Count, IPs: row.IPs, Enabled: false})
	}
	return rows, events, err
}

// toggleRule enables and disables a rule.
//
// A rule that is cutting off live people gets turned off in the minute it
// is noticed — not when someone finds where rules.json lives on somebody
// else's server. Hence the button; hence no condition editor.
func (s *Server) toggleRule(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	if s.o.Rules == nil {
		http.Error(w, s.t(r, "error.rules_off"), http.StatusNotFound)
		return
	}

	id := r.PostFormValue("id")
	enable := r.PostFormValue("enable") == "yes"

	if err := s.o.Rules.Toggle(id, enable); err != nil {
		s.o.Log.Error("the rule was not toggled", "rule", id, "who", who, "err", err)
		http.Redirect(w, r, withError(backTo(r), err.Error()), http.StatusSeeOther)
		return
	}
	s.reload(r.Context(), control.ReloadRules)

	// Who turned what on goes into the node's log: a change of protection
	// must not happen anonymously.
	s.o.Log.Info("a rule was toggled from the admin UI",
		"rule", id, "enabled", enable, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// backTo is where a rule's form returns: the rule's own page when it was
// sent from there, the list otherwise. The form names a rule, never an
// address, so the field cannot become a redirect anywhere else.
func backTo(r *http.Request) string {
	if id := r.PostFormValue("back"); id != "" {
		return "/rule?id=" + url.QueryEscape(id)
	}
	return "/rules"
}

func withError(to, message string) string {
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	return to + sep + "error=" + url.QueryEscape(message)
}

// setRuleMode moves a rule between shadow and active. It is the step that
// puts a rule to work: the node never takes it by itself, and neither
// does a proposal from the cloud.
func (s *Server) setRuleMode(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	if s.o.Rules == nil {
		http.Error(w, s.t(r, "error.rules_off"), http.StatusNotFound)
		return
	}

	id := r.PostFormValue("id")
	mode := r.PostFormValue("mode")

	if err := s.o.Rules.SetMode(id, mode); err != nil {
		s.o.Log.Error("the rule's mode was not changed", "rule", id, "mode", mode, "who", who, "err", err)
		http.Redirect(w, r, withError(backTo(r), err.Error()), http.StatusSeeOther)
		return
	}
	s.reload(r.Context(), control.ReloadRules)

	s.o.Log.Info("a rule's mode was changed from the admin UI",
		"rule", id, "mode", mode, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, backTo(r), http.StatusSeeOther)
}

// --- helpers ---

func (s *Server) common(r *http.Request, user, section string, period time.Duration, message string) pageCommon {
	c := pageCommon{
		User: user, Version: s.o.Version, Section: section, Error: message,
		APITokens: s.o.Tokens != nil, Back: backOf(r),
	}
	// One question to the core per page: its answer is the bell, and its
	// absence is the warning that the core is down.
	state, err := s.coreAlerts(context.Background())
	switch {
	case err != nil:
		c.CoreDown = true
	case state.Enabled:
		c.Bell = bell(state)
	}
	if period > 0 {
		c.Period = shortPeriod(period)
	}
	return c
}

// periodOf reads ?period=24h. The default is a day: a shorter span cannot
// be judged by night traffic, and a longer one takes noticeably more time
// to summarize.
func periodOf(r *http.Request) time.Duration {
	period := 24 * time.Hour
	if s := r.URL.Query().Get("period"); s != "" {
		if d, err := time.ParseDuration(s); err == nil && d > 0 && d <= 90*24*time.Hour {
			period = d
		}
	}
	return period
}

func shortPeriod(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return d.String()
	}
}
