package admin

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/summary"
)

//go:embed templates/*.html templates/style.css
var templatesFS embed.FS

const (
	sessionCookieName = "antibot_session"
	csrfCookieName    = "antibot_csrf"
)

func parseTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"share":    share,
		"time":     formatTime,
		"truncate": truncate,
		"lower":    lower,
		"count":    thousands,
		"bytes":    formatBytes,
		"latency":  formatLatency,
		"title": func(section string) string {
			switch section {
			case "events":
				return "Events"
			case "rules":
				return "Rules"
			default:
				return "Overview"
			}
		},
		// breakdown assembles the data for one breakdown table: Go
		// templates have no other way to pass several values. key is the
		// events filter a row links to; extra is one more filter as a
		// name and a value, so that a path with 5xx opens exactly its 5xx.
		"breakdown": func(name, key string, rows []summary.Row, extra ...string) map[string]any {
			data := map[string]any{"Name": name, "Key": key, "Rows": rows}
			if len(extra) == 2 {
				data["ExtraKey"], data["ExtraValue"] = extra[0], extra[1]
			}
			return data
		},
	}
	return template.New("").Funcs(funcs).ParseFS(templatesFS, "templates/*.html")
}

// pageCommon is what every page carries.
type pageCommon struct {
	User    string
	Version string
	Section string
	Period  string
	Error   string
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
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
		http.Error(w, "it did not work out", http.StatusInternalServerError)
		return
	}
	s.render(w, "login.html", loginData{
		pageCommon: pageCommon{
			Version: s.o.Version,
			Error:   r.URL.Query().Get("error"),
		},
		CSRF: token,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}

	// Password guessing is limited by address rather than by name: the
	// name is guessed together with the password, and counting by name
	// would not notice such guessing.
	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		s.o.Log.Warn("too many admin UI login attempts", "address", clientAddr(r))
		http.Error(w, "Too many attempts. Please wait.", http.StatusTooManyRequests)
		return
	}

	name := r.PostFormValue("name")
	password := r.PostFormValue("password")

	if !s.o.Users.Check(name, password) {
		s.o.Log.Warn("a failed admin UI login", "name", name, "address", clientAddr(r))
		http.Redirect(w, r, "/login?error="+
			url.QueryEscape("The name or the password did not match"), http.StatusSeeOther)
		return
	}

	key, until, err := s.o.Sessions.Start(name, now)
	if err != nil {
		http.Error(w, "it did not work out", http.StatusInternalServerError)
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
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
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

	ServerErrors int
	Answers      donutChart
	Series       *columnsChart
}

func (s *Server) overviewPage(w http.ResponseWriter, r *http.Request, user string) {
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
		s.render(w, "overview.html", overviewData{
			pageCommon: s.common(user, "overview", period, err.Error()),
			CSRF:       s.csrfToken(r),
			Summary:    &summary.Summary{Decisions: map[string]int{}},
		})
		return
	}

	data := overviewData{
		pageCommon:   s.common(user, "overview", period, ""),
		CSRF:         s.csrfToken(r),
		Summary:      result,
		ServerErrors: result.Answers[summary.AnswerServerError],
		Answers:      newDonut(result.Answers),
		Series:       newColumns(result.Series, period),
	}
	if s.o.Rules != nil {
		set := s.o.Rules.Set()
		data.Rules = len(set.All())
		data.Effective = len(set.Effective())
	}
	s.render(w, "overview.html", data)
}

// --- events ---

type eventsData struct {
	pageCommon
	CSRF   string
	Events []facts.Request
	Filter summary.Filter
	Limit  int
}

func (s *Server) eventsPage(w http.ResponseWriter, r *http.Request, user string) {
	f := summary.Filter{
		Host:     r.URL.Query().Get("host"),
		Decision: r.URL.Query().Get("decision"),
		Rule:     r.URL.Query().Get("rule"),
		IP:       r.URL.Query().Get("ip"),
		JA4:      r.URL.Query().Get("ja4"),
		Search:   r.URL.Query().Get("q"),
		Status:   r.URL.Query().Get("status"),
	}
	limit := 200

	list, err := summary.Latest(s.o.EventsDir, f, limit)
	message := ""
	if err != nil {
		message = err.Error()
	}

	s.render(w, "events.html", eventsData{
		pageCommon: s.common(user, "events", 0, message),
		CSRF:       s.csrfToken(r),
		Events:     list,
		Filter:     f,
		Limit:      limit,
	})
}

// --- rules ---

// RuleRow is a rule together with how many times it fired over the
// period.
type RuleRow struct {
	Rule    rules.Rule
	Matched int
	IPs     int
	Enabled bool
}

type rulesData struct {
	pageCommon
	CSRF   string
	Rules  []RuleRow
	Events int
}

func (s *Server) rulesPage(w http.ResponseWriter, r *http.Request, user string) {
	period := periodOf(r)
	now := time.Now()

	data := rulesData{
		pageCommon: s.common(user, "rules", period, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
	}
	if s.o.Rules == nil {
		s.render(w, "rules.html", data)
		return
	}

	// How often a rule fired comes from the log rather than from
	// in-memory counters: after a restart the counters reset while the
	// log stays.
	fired := map[string]summary.Row{}
	result, err := summary.Build(summary.Options{
		Dir: s.o.EventsDir, From: now.Add(-period), To: now,
		Top: 1000,
	})
	if err != nil {
		data.Error = err.Error()
	} else {
		data.Events = result.Events
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
	for _, rule := range set.Effective() {
		row := fired[rule.ID]
		data.Rules = append(data.Rules, RuleRow{
			Rule: rule, Matched: row.Count, IPs: row.IPs, Enabled: true,
		})
	}
	for _, rule := range set.All() {
		if _, ok := effective[rule.ID]; ok {
			continue
		}
		row := fired[rule.ID]
		data.Rules = append(data.Rules, RuleRow{
			Rule: rule, Matched: row.Count, IPs: row.IPs, Enabled: false,
		})
	}

	s.render(w, "rules.html", data)
}

// toggleRule enables and disables a rule.
//
// A rule that is cutting off live people gets turned off in the minute it
// is noticed — not when someone finds where rules.json lives on somebody
// else's server. Hence the button; hence no condition editor.
func (s *Server) toggleRule(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.o.Rules == nil {
		http.Error(w, "the rules are not connected", http.StatusNotFound)
		return
	}

	id := r.PostFormValue("id")
	enable := r.PostFormValue("enable") == "yes"

	if err := s.o.Rules.Toggle(id, enable); err != nil {
		s.o.Log.Error("the rule was not toggled", "rule", id, "who", who, "err", err)
		http.Redirect(w, r, "/rules?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}

	// Who turned what on goes into the node's log: a change of protection
	// must not happen anonymously.
	s.o.Log.Info("a rule was toggled from the admin UI",
		"rule", id, "enabled", enable, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/rules", http.StatusSeeOther)
}

// --- helpers ---

func (s *Server) common(user, section string, period time.Duration, message string) pageCommon {
	c := pageCommon{
		User: user, Version: s.o.Version, Section: section, Error: message,
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
