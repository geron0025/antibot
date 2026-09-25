package admin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/i18n"
)

type alertRow struct {
	alerts.Trigger
	Firing []alerts.Status
}

type alertsData struct {
	pageCommon
	CSRF    string
	Rows    []alertRow
	History []alerts.Entry

	// Delivering says a command is set: without one the alerts go only
	// to the log and to this page.
	Delivering bool

	// Off says the core's settings turn the alerts off.
	Off bool
}

// deliveryData is the settings tab that says where the alerts go.
type deliveryData struct {
	pageCommon
	CSRF string

	// Command is the command in force and Source where it comes from:
	// "config" — config.yaml, changed only there; "admin" — set here.
	Command   string
	Source    string
	UpdatedBy string
	UpdatedAt time.Time
	CanEdit   bool

	TestResult string
}

func (s *Server) alertsPage(w http.ResponseWriter, r *http.Request, user string) {
	// A core that does not answer is said so by the header of the page;
	// here it is only an empty page, not alerts that are off.
	state, err := s.coreAlerts(r.Context())
	firing := state.Firing
	p := s.printer(r)
	var rows []alertRow
	for _, t := range state.Triggers {
		row := alertRow{Trigger: wordTrigger(p, t)}
		for _, f := range firing {
			if f.Kind == t.Kind {
				row.Firing = append(row.Firing, f)
			}
		}
		rows = append(rows, row)
	}

	data := alertsData{
		pageCommon: s.common(r, user, "alerts", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
		Rows:       rows,
		History:    state.History,
		Off:        err == nil && !state.Enabled,
	}
	if state.ConfigCommand != "" {
		data.Delivering = true
	} else if s.o.AlertCommand != nil {
		c, err := s.o.AlertCommand.Get()
		if err != nil && data.Error == "" {
			data.Error = err.Error()
		}
		data.Delivering = c.Command != ""
	}
	s.render(w, r, "alerts.html", data)
}

// triggerTexts word each trigger in the viewer's language: its title,
// and its condition built from the numbers the core sends. spans are the
// positions of the numbers that are seconds.
var triggerTexts = map[string]struct {
	title, when string
	args        int
	spans       []int
}{
	alerts.SiteDown:      {"trigger.site_down", "trigger.site_down_when", 3, []int{2}},
	alerts.RuleSpike:     {"trigger.rule_spike", "trigger.rule_spike_when", 3, []int{1}},
	alerts.RequestsSpike: {"trigger.requests_spike", "trigger.requests_spike_when", 3, []int{1}},
	alerts.BlockedSpike:  {"trigger.blocked_spike", "trigger.blocked_spike_when", 3, []int{1}},
	alerts.CertExpiring:  {"trigger.cert_expiring", "trigger.cert_expiring_when", 1, nil},
	alerts.EventsDropped: {"trigger.events_dropped", "trigger.events_dropped_when", 1, []int{0}},
	alerts.DiskLow:       {"trigger.disk_low", "trigger.disk_low_when", 1, nil},
	alerts.FactsStale:    {"trigger.facts_stale", "trigger.facts_stale_when", 1, []int{0}},
	alerts.OutboxStuck:   {"trigger.outbox_stuck", "trigger.outbox_stuck_when", 1, nil},
}

// wordTrigger puts a trigger in the viewer's language. A kind the admin
// UI does not know, or a core too old to send the numbers, keeps the
// core's own words.
func wordTrigger(p *i18n.Printer, t alerts.Trigger) alerts.Trigger {
	text, ok := triggerTexts[t.Kind]
	if !ok {
		return t
	}
	t.Title = p.T(text.title)
	if len(t.Args) != text.args {
		return t
	}
	args := make([]any, len(t.Args))
	for i, v := range t.Args {
		if slices.Contains(text.spans, i) {
			args[i] = span(p, v)
		} else {
			args[i] = v
		}
	}
	t.When = p.T(text.when, args...)
	return t
}

func (s *Server) deliveryPage(w http.ResponseWriter, r *http.Request, user string) {
	s.renderDelivery(w, r, user, r.URL.Query().Get("error"), "")
}

func (s *Server) renderDelivery(w http.ResponseWriter, r *http.Request, user, message, test string) {
	data := deliveryData{
		pageCommon: s.common(r, user, "settings", 0, message),
		CSRF:       s.csrfToken(r),
		TestResult: test,
	}
	data.Tab = "alerts"
	state, _ := s.coreAlerts(r.Context())
	switch {
	case state.ConfigCommand != "":
		data.Command, data.Source = state.ConfigCommand, "config"
	case s.o.AlertCommand != nil:
		c, err := s.o.AlertCommand.Get()
		if err != nil && data.Error == "" {
			data.Error = err.Error()
		}
		data.Command, data.UpdatedBy, data.UpdatedAt, data.CanEdit = c.Command, c.UpdatedBy, c.UpdatedAt, true
		if c.Command != "" {
			data.Source = "admin"
		}
	}
	s.render(w, r, "delivery.html", data)
}

// setAlertCommand asks for the password once more. The command runs on
// the node's machine: a stolen session must not become a way to run code
// there — the same reason a token is issued only against the password.
func (s *Server) setAlertCommand(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	state, err := s.coreAlerts(r.Context())
	if err != nil {
		s.alertsError(w, r, s.t(r, "delivery.core_down"))
		return
	}
	if state.ConfigCommand != "" || s.o.AlertCommand == nil {
		s.alertsError(w, r, s.t(r, "delivery.in_config"))
		return
	}

	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		http.Error(w, s.t(r, "error.too_many_attempts"), http.StatusTooManyRequests)
		return
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("the alert command was not changed: the password did not match",
			"who", who, "address", clientAddr(r))
		s.alertsError(w, r, s.t(r, "error.password"))
		return
	}

	// A textarea sends CRLF; the shell wants LF.
	command := strings.TrimSpace(strings.ReplaceAll(r.PostFormValue("command"), "\r\n", "\n"))
	if err := s.o.AlertCommand.Set(command, who, now); err != nil {
		s.alertsError(w, r, err.Error())
		return
	}
	// The command itself stays out of the log: it often carries a bot's
	// token or a mail password. Its fingerprint says which one it was.
	sum := sha256.Sum256([]byte(command))
	s.o.Log.Warn("the alert command was changed from the admin UI",
		"who", who, "address", clientAddr(r), "bytes", len(command), "sha256", hex.EncodeToString(sum[:6]))
	http.Redirect(w, r, "/settings/alerts", http.StatusSeeOther)
}

func (s *Server) testAlert(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	result, err := s.o.Core.TestAlert(ctx)
	if err != nil {
		result = s.t(r, "delivery.not_sent", err.Error())
	}
	s.o.Log.Info("a test alert was sent from the admin UI", "who", who, "address", clientAddr(r), "result", result)
	s.renderDelivery(w, r, who, "", result)
}

func (s *Server) alertsError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/settings/alerts?error="+url.QueryEscape(message), http.StatusSeeOther)
}
