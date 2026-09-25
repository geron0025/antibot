package admin

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/i18n"
)

// textOnlyCore is a core from before the messages came as keys: only
// its own words.
type textOnlyCore struct{ control.Core }

func (c textOnlyCore) Alerts(ctx context.Context) (control.Alerts, error) {
	a, err := c.Core.Alerts(ctx)
	for i := range a.Firing {
		a.Firing[i].Message.Key = ""
	}
	for i := range a.History {
		a.History[i].Message.Key = ""
	}
	return a, err
}

// The core words its messages in the delivery language; the admin UI
// words the same messages in the language of whoever looks.
func TestAlertTextsSpeakTheViewersLanguage(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	now := time.Now()
	for i := 0; i < 30; i++ {
		local(s).Watcher.Write(facts.Request{Time: now.Add(-2 * time.Minute), Decision: "pass", Status: 502})
	}
	local(s).Watcher.Check(now)

	cookies := logIn(t, s)
	ru := withLang(cookies, "ru")
	for _, path := range []string{"/", "/rules", "/alerts"} {
		_, body := getAs(t, s, path, ru, "")
		if !strings.Contains(body, "сайт отвечает ошибками: 30 из 30") {
			t.Errorf("%s in Russian does not word the alert in Russian", path)
		}
		if strings.Contains(body, "the site answers with errors") {
			t.Errorf("%s in Russian still shows the English text", path)
		}
	}
	_, body := getAs(t, s, "/alerts", withLang(cookies, "en"), "")
	if !strings.Contains(body, "the site answers with errors: 30 of 30") {
		t.Error("the English page lost the English text")
	}

	s.o.Core = textOnlyCore{s.o.Core}
	_, body = getAs(t, s, "/alerts", ru, "")
	if !strings.Contains(body, "the site answers with errors: 30 of 30") {
		t.Error("without a key the core's own text is not shown")
	}
}

// The language of the messages is chosen next to the command, and the
// admin UI's own language is offered while none was saved.
func TestTheDeliveryTabSetsTheLanguage(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	s.o.Language = i18n.RU
	cookies := withLang(logIn(t, s), "en")

	_, body := getAs(t, s, "/settings/alerts", cookies, "")
	if !strings.Contains(body, `name="language"`) || !strings.Contains(body, `<option value="ru" selected>`) {
		t.Fatalf("no choice of language, or admin.yaml's is not offered: %s", body)
	}

	rec := alertsPost(t, s, cookies, "/settings/alerts/command",
		url.Values{"command": {"true"}, "language": {"de"}, "password": {password}})
	if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("an unknown language: %d %v", rec.Code, rec.Header())
	}
	rec = alertsPost(t, s, cookies, "/settings/alerts/command",
		url.Values{"command": {"true"}, "language": {"en"}, "password": {password}})
	if rec.Code != http.StatusSeeOther || strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("save: %d %v", rec.Code, rec.Header())
	}
	if c, _ := s.o.AlertCommand.Get(); c.Command != "true" || c.Language != "en" {
		t.Fatalf("%+v", c)
	}
	_, body = getAs(t, s, "/settings/alerts", cookies, "")
	if !strings.Contains(body, `<option value="en" selected>`) {
		t.Error("the saved language is not the one selected")
	}

	// The core takes it up with the next message.
	rec = alertsPost(t, s, cookies, "/settings/alerts/test", url.Values{})
	if h := local(s).Watcher.History(); len(h) == 0 || h[0].Language != i18n.EN {
		t.Fatalf("the test message: %d %+v", rec.Code, h)
	}
}

// A language written into config.yaml is shown and not offered for change.
func TestConfigAlertLanguageWins(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	local(s).ConfigLanguage = "ru"
	cookies := logIn(t, s)
	_, body := getAs(t, s, "/settings/alerts", cookies, "en-US")
	if strings.Contains(body, `name="language"`) || !strings.Contains(body, "alerts.language") {
		t.Fatalf("%s", body)
	}
}
