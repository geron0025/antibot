package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
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
	s.renderAlerts(w, r, user, r.URL.Query().Get("error"), "")
}

func (s *Server) renderAlerts(w http.ResponseWriter, r *http.Request, user, message, test string) {
	firing := s.o.Alerts.Firing()
	var rows []alertRow
	for _, t := range s.o.Alerts.Triggers() {
		row := alertRow{Trigger: t}
		for _, f := range firing {
			if f.Kind == t.Kind {
				row.Firing = append(row.Firing, f)
			}
		}
		rows = append(rows, row)
	}

	data := alertsData{
		pageCommon: s.common(user, "alerts", 0, message),
		CSRF:       s.csrfToken(r),
		Rows:       rows,
		History:    s.o.Alerts.History(),
		TestResult: test,
	}
	switch {
	case s.o.ConfigAlertCommand != "":
		data.Command, data.Source = s.o.ConfigAlertCommand, "config"
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
	s.render(w, "alerts.html", data)
}

// setAlertCommand asks for the password once more. The command runs on
// the node's machine: a stolen session must not become a way to run code
// there — the same reason a token is issued only against the password.
func (s *Server) setAlertCommand(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.o.ConfigAlertCommand != "" || s.o.AlertCommand == nil {
		s.alertsError(w, r, "The command is set in config.yaml and is changed only there")
		return
	}

	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		http.Error(w, "Too many attempts. Please wait.", http.StatusTooManyRequests)
		return
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("the alert command was not changed: the password did not match",
			"who", who, "address", clientAddr(r))
		s.alertsError(w, r, "The password did not match")
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
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}

func (s *Server) testAlert(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	result := s.o.Alerts.Test(r.Context())
	s.o.Log.Info("a test alert was sent from the admin UI", "who", who, "address", clientAddr(r), "result", result)
	s.renderAlerts(w, r, who, "", result)
}

func (s *Server) alertsError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/alerts?error="+url.QueryEscape(message), http.StatusSeeOther)
}
