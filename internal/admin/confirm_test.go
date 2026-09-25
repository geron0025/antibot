package admin

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/rules"
)

// The one script is served from the admin UI itself, and the CSP lets in
// that and nothing else: no inline script, nothing from outside.
func TestTheConfirmScript(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/confirm.js", nil))
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/javascript") ||
		!strings.Contains(rec.Body.String(), "showModal") {
		t.Fatalf("%d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") {
		t.Fatalf("CSP: %s", csp)
	}
}

// The dialog is in the page, in the page's language; the script only
// wires it.
func TestTheConfirmDialogIsOnThePages(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	cookies := withLang(logIn(t, s), "ru")
	for _, path := range []string{"/settings/core", "/rules", "/"} {
		_, body := getAs(t, s, path, cookies, "")
		for _, want := range []string{`<dialog id="confirm"`, "Подтвердить", "Отмена", `<script src="/confirm.js" defer></script>`} {
			if !strings.Contains(body, want) {
				t.Errorf("%s has no %q", path, want)
			}
		}
	}
	_, body := getAs(t, s, "/settings/core", cookies, "")
	if !strings.Contains(body, `data-confirm="`) || !strings.Contains(body, `class="password-field"`) {
		t.Error("the restart form does not ask through the dialog")
	}
}

var (
	formPattern     = regexp.MustCompile(`(?s)<form\b[^>]*>.*?</form>`)
	passwordPattern = regexp.MustCompile(`name="password"`)
)

// Every form that asks for the password again asks through the dialog,
// and keeps its own field for a browser without the script.
func TestEveryPasswordFormAsksThroughTheDialog(t *testing.T) {
	files, _ := fs.Glob(templatesFS, "templates/*.html")
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "login.html") {
			continue
		}
		raw, _ := templatesFS.ReadFile(name)
		for _, form := range formPattern.FindAllString(string(raw), -1) {
			if !passwordPattern.MatchString(form) {
				continue
			}
			found++
			open := form[:strings.Index(form, ">")]
			if !strings.Contains(open, "data-confirm=") {
				t.Errorf("%s: a password form without data-confirm: %s", name, open)
			}
			if !strings.Contains(form, `class="password-field"`) {
				t.Errorf("%s: the password field is not in .password-field: %s", name, open)
			}
		}
	}
	// Four that asked before, four more: domains, tokens, the cloud, and
	// the move to active on two pages.
	if found < 9 {
		t.Errorf("only %d password forms", found)
	}
}

// The destructive actions ask for the password again, and a wrong one
// changes nothing.
func TestDestructiveActionsAskForThePassword(t *testing.T) {
	t.Run("removing a domain", func(t *testing.T) {
		s, _ := newDomainsServer(t)
		cookies := logIn(t, s)
		csrf := tokenFrom(cookies)
		form := url.Values{"csrf": {csrf}, "host": {"here.example.ru"}, "server": {"127.0.0.1:3000"}}
		postForm(t, s, "/domains/add", cookies, form)
		for _, wrong := range []string{"", "not the password"} {
			rec := postForm(t, s, "/domains/remove", cookies, url.Values{"csrf": {csrf}, "host": {"here.example.ru"}, "password": {wrong}})
			if errorOf(rec) == "" {
				t.Fatalf("%q: no refusal", wrong)
			}
		}
		if _, ok := s.o.Domains.Routes()["here.example.ru"]; !ok {
			t.Fatal("removed without the password")
		}
		postForm(t, s, "/domains/remove", cookies, url.Values{"csrf": {csrf}, "host": {"here.example.ru"}, "password": {password}})
		if _, ok := s.o.Domains.Routes()["here.example.ru"]; ok {
			t.Fatal("not removed with the password")
		}
	})

	t.Run("revoking a token", func(t *testing.T) {
		s, read, _ := newAPIServer(t)
		cookies := logIn(t, s)
		csrf := tokenFrom(cookies)
		rec := postForm(t, s, "/settings/tokens/revoke", cookies, url.Values{"csrf": {csrf}, "name": {"monitoring"}, "password": {"nope"}})
		if !strings.Contains(rec.Header().Get("Location"), "error") {
			t.Fatalf("%d %v", rec.Code, rec.Header())
		}
		if rec := call(t, s, "GET", "/api/v1/rules", read, ""); rec.Code != http.StatusOK {
			t.Fatal("revoked without the password")
		}
		postForm(t, s, "/settings/tokens/revoke", cookies, url.Values{"csrf": {csrf}, "name": {"monitoring"}, "password": {password}})
		if rec := call(t, s, "GET", "/api/v1/rules", read, ""); rec.Code != http.StatusUnauthorized {
			t.Fatal("not revoked with the password")
		}
	})

	t.Run("forgetting the cloud token", func(t *testing.T) {
		state := &CloudState{Token: true, Answered: true, Fetching: true}
		link := &fakeControl{state: state}
		s := withCloud(t, state, link)
		cookies := logIn(t, s)
		// The form carries the token, and the page checks it.
		for _, path := range []string{"/settings/cloud/forget", "/settings/cloud/save"} {
			if rec := postForm(t, s, path, cookies, url.Values{"password": {password}, "facts": {"1"}}); rec.Code != http.StatusForbidden {
				t.Fatalf("%s without the token: %d", path, rec.Code)
			}
		}
		resp := postCloud(t, s, "/settings/cloud/forget", cookies, url.Values{"password": {"nope"}})
		if !strings.Contains(resp.Header.Get("Location"), "error") || link.forgotten != 0 {
			t.Fatalf("%v, forgotten %d", resp.Header, link.forgotten)
		}
		postCloud(t, s, "/settings/cloud/forget", cookies, url.Values{"password": {password}})
		if link.forgotten != 1 {
			t.Fatal("not forgotten with the password")
		}
	})

	t.Run("moving a rule to active", func(t *testing.T) {
		s, _ := newServer(t)
		cookies := logIn(t, s)
		csrf := tokenFrom(cookies)
		mode := func() string { return s.o.Rules.Set().All()[0].Mode }
		// Back to shadow is a step towards safety: no password.
		postForm(t, s, "/rules/mode", cookies, url.Values{"csrf": {csrf}, "id": {"block-curl"}, "mode": {rules.Shadow}})
		if mode() != rules.Shadow {
			t.Fatal("shadow needed a password")
		}
		rec := postForm(t, s, "/rules/mode", cookies, url.Values{"csrf": {csrf}, "id": {"block-curl"}, "mode": {rules.Active}})
		if !strings.Contains(rec.Header().Get("Location"), "error") || mode() != rules.Shadow {
			t.Fatalf("to active without the password: %v, %s", rec.Header(), mode())
		}
		postForm(t, s, "/rules/mode", cookies, url.Values{"csrf": {csrf}, "id": {"block-curl"}, "mode": {rules.Active}, "password": {password}})
		if mode() != rules.Active {
			t.Fatal("not active with the password")
		}
	})
}
