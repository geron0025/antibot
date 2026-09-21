package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/facts"
)

// newAlertsServer is the test admin UI with triggers and a command file
// whose command, once set, writes where the test can see it.
func newAlertsServer(t *testing.T, configCommand string) (*Server, string) {
	t.Helper()
	s, dir := newServer(t)
	file, err := alerts.OpenCommand(filepath.Join(dir, "alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.o.AlertCommand, local(s).ConfigCommand = file, configCommand
	local(s).Watcher = alerts.New(alerts.Options{
		Window: 5 * time.Minute, SiteErrorShare: 0.5, SiteMinRequests: 20, SpikeFactor: 5,
		SpikeMinRequests: 500, SpikeMinBlocked: 200, RuleMinMatches: 50, CertDays: 14,
		Timeout: 5 * time.Second,
		Command: func() string {
			if configCommand != "" {
				return configCommand
			}
			c, _ := file.Get()
			return c.Command
		},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	return s, dir
}

func alertsPost(t *testing.T, s *Server, cookies []*http.Cookie, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	for _, c := range cookies {
		if c.Name == csrfCookieName && form.Get("csrf") == "" {
			form.Set("csrf", c.Value)
		}
	}
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// The command is set only against the password, and a test message runs
// it at once.
func TestAlertsPage(t *testing.T) {
	s, dir := newAlertsServer(t, "")
	cookies := logIn(t, s)

	page := get(t, s, "/alerts", cookies)
	body, _ := io.ReadAll(page.Body)
	for _, want := range []string{"the site does not answer", "a rule cuts off a lot",
		"No command yet", `href="/settings/alerts"`, "nothing since the start"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the page does not contain %q", want)
		}
	}

	// Delivery is a tab of the settings, not a part of the alerts page.
	body, _ = io.ReadAll(get(t, s, "/settings/alerts", cookies).Body)
	for _, want := range []string{"Delivery", `action="/settings/alerts/command"`,
		`href="/settings" class="current">Settings</a>`, `href="/settings/alerts" class="current"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the delivery tab does not contain %q", want)
		}
	}

	marker := filepath.Join(dir, "delivered")
	command := `printf '%s' "$ANTIBOT_ALERT_STATE" > '` + marker + `'`

	rec := alertsPost(t, s, cookies, "/settings/alerts/command", url.Values{"command": {command}, "password": {"not the password"}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("a wrong password: %d %v", rec.Code, rec.Header())
	}
	if c, _ := s.o.AlertCommand.Get(); c.Command != "" {
		t.Fatal("the command was set against a wrong password")
	}

	rec = alertsPost(t, s, cookies, "/settings/alerts/command", url.Values{"command": {command}, "password": {password}})
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("set: %d %v", rec.Code, rec.Header())
	}
	if c, _ := s.o.AlertCommand.Get(); c.Command != command || c.UpdatedBy != "owner" {
		t.Fatalf("%+v", c)
	}

	rec = alertsPost(t, s, cookies, "/settings/alerts/test", url.Values{})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "handed to the command") {
		t.Fatalf("test: %d %s", rec.Code, rec.Body)
	}
	if got, _ := os.ReadFile(marker); string(got) != alerts.Test {
		t.Fatalf("the command got %q", got)
	}

	if rec := alertsPost(t, s, cookies, "/settings/alerts/test", url.Values{"csrf": {"forged"}}); rec.Code != http.StatusForbidden {
		t.Fatalf("a forged form: %d", rec.Code)
	}
}

// The bell is in the header of every page: quiet while nothing fires, a
// count and the trigger once something does, and the latest messages.
func TestTheBell(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	cookies := logIn(t, s)

	for _, path := range []string{"/", "/rules", "/events", "/alerts"} {
		body, _ := io.ReadAll(get(t, s, path, cookies).Body)
		page := string(body)
		bell := `class="bell"`
		if path == "/alerts" {
			bell = `class="bell current"`
		}
		if !strings.Contains(page, bell) || !strings.Contains(page, "Nothing is firing") {
			t.Errorf("%s: no quiet bell", path)
		}
		// The bell is the way to the alerts page; neither the menu nor its
		// burger has a second one.
		for _, open := range []string{"<nav>", `<nav class="drop burger-menu"`} {
			start := strings.Index(page, open)
			if start < 0 {
				t.Fatalf("%s: no %s", path, open)
			}
			nav := page[start : start+strings.Index(page[start:], "</nav>")]
			if strings.Contains(nav, "/alerts") {
				t.Errorf("%s: %s duplicates the bell", path, open)
			}
		}
	}

	now := time.Now()
	for i := 0; i < 30; i++ {
		local(s).Watcher.Write(facts.Request{Time: now.Add(-2 * time.Minute), Decision: "pass", Status: 502})
	}
	local(s).Watcher.Check(now)

	body, _ := io.ReadAll(get(t, s, "/rules", cookies).Body)
	page := string(body)
	for _, want := range []string{`class="bell firing"`, `class="bell-count">1<`, "site_down", "Latest messages",
		"the site answers with errors"} {
		if !strings.Contains(page, want) {
			t.Errorf("the bell does not show %q", want)
		}
	}

	// No alerts, no bell.
	local(s).Watcher = nil
	body, _ = io.ReadAll(get(t, s, "/", cookies).Body)
	if strings.Contains(string(body), `class="bell`) {
		t.Error("a bell without alerts")
	}
}

// A command written into config.yaml is shown and never replaced from
// the admin UI, not even with the password.
func TestConfigAlertCommandWins(t *testing.T) {
	s, _ := newAlertsServer(t, "logger antibot")
	cookies := logIn(t, s)

	body, _ := io.ReadAll(get(t, s, "/settings/alerts", cookies).Body)
	if !strings.Contains(string(body), "changed only there") || strings.Contains(string(body), `action="/settings/alerts/command"`) {
		t.Fatalf("%s", body)
	}
	rec := alertsPost(t, s, cookies, "/settings/alerts/command", url.Values{"command": {"true"}, "password": {password}})
	if !strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	if c, _ := s.o.AlertCommand.Get(); c.Command != "" {
		t.Fatal("the file was written over the configuration")
	}
}
