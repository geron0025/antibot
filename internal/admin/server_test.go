package admin

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/summary"
)

const password = "a very long password"

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	dir := t.TempDir()

	users, err := OpenUsers(filepath.Join(dir, "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := users.Set("owner", password); err != nil {
		t.Fatal(err)
	}

	l, err := events.Open(events.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Write(facts.Request{
		Time: now.Add(-time.Minute), IP: "203.0.113.1", Host: "a.ru",
		Path: "/product", UA: "Mozilla/5.0 (compatible; Googlebot/2.1)",
		JA4: "t13d1516h2", Decision: "pass", Status: 200, Bytes: 2048,
		Duration: 30 * time.Millisecond,
	})
	l.Write(facts.Request{
		Time: now, IP: "198.51.100.9", Host: "a.ru", Path: "/api",
		UA: "curl/8.4", JA4: "t13d0000", Decision: "block", Rule: "block-curl",
		Shadow: []string{"watch-everything"}, Status: 403,
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := rules.Open(filepath.Join(dir, "rules.json"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err := store.Write([]rules.Rule{
		{ID: "block-curl", Scope: []string{"*"}, Mode: rules.Active, Priority: 100,
			Enabled:   &enabled,
			Condition: rules.Condition{Field: "ua", Op: "contains", Value: []byte(`"curl"`)},
			Action:    rules.Action{Type: rules.Block}},
	}); err != nil {
		t.Fatal(err)
	}

	s, err := New(Options{
		Addr: "127.0.0.1:0", Users: users, Sessions: NewSessions(time.Hour),
		Attempts: rules.NewWindows(), EventsDir: dir,
		Rules: store, Version: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

// logIn walks a human's path: the login page, the form, the session
// cookie.
func logIn(t *testing.T, s *Server) []*http.Cookie {
	t.Helper()
	h := s.Handler()

	req := httptest.NewRequest("GET", "/login", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	cookies := resp.Result().Cookies()
	var csrf string
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			csrf = c.Value
		}
	}
	if csrf == "" {
		t.Fatal("the login page did not set a token")
	}

	form := url.Values{"name": {"owner"}, "password": {password}, "csrf": {csrf}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	if resp.Code != http.StatusSeeOther {
		t.Fatalf("the login returned %d rather than a redirect: %s", resp.Code, resp.Body)
	}
	return append(cookies, resp.Result().Cookies()...)
}

func get(t *testing.T, s *Server, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp.Result()
}

// The main property of the admin UI: without a login nothing is visible.
func TestWithoutALoginNothingIsVisible(t *testing.T) {
	s, _ := newServer(t)
	for _, path := range []string{"/", "/events", "/rules"} {
		resp := get(t, s, path, nil)
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("%s without a login returned %d rather than a redirect to the login", path, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "203.0.113.1") {
			t.Errorf("%s without a login showed events", path)
		}
	}
}

func TestLoginAndPages(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	checks := map[string][]string{
		"/":       {"requests", "What the node does not know", "googlebot"},
		"/events": {"203.0.113.1", "block-curl", "watch-everything", "/product"},
		"/rules":  {"block-curl", "active", "antibot rules"},
	}
	for path, want := range checks {
		resp := get(t, s, path, cookies)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s returned %d", path, resp.StatusCode)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		for _, piece := range want {
			if !strings.Contains(string(body), piece) {
				t.Errorf("%s does not contain %q", path, piece)
			}
		}
	}
}

func TestAWrongPasswordLetsNobodyIn(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	req := httptest.NewRequest("GET", "/login", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	cookies := resp.Result().Cookies()
	csrf := cookies[0].Value

	form := url.Values{"name": {"owner"}, "password": {"the wrong password"}, "csrf": {csrf}}
	req = httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp = httptest.NewRecorder()
	h.ServeHTTP(resp, req)

	for _, c := range resp.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Fatal("a wrong password produced a session")
		}
	}
}

// A form without a token is a request that did not come from our page.
func TestAFormWithoutATokenIsNotAccepted(t *testing.T) {
	s, _ := newServer(t)
	form := url.Values{"name": {"owner"}, "password": {password}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)

	if resp.Code != http.StatusForbidden {
		t.Errorf("a login without a token returned %d, want 403", resp.Code)
	}
}

func TestLoggingOutClosesTheSession(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	form := url.Values{"csrf": {tokenFrom(cookies)}}
	req := httptest.NewRequest("POST", "/logout", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)

	if s.o.Sessions.Live() != 0 {
		t.Error("the session is alive after logging out")
	}
	if get(t, s, "/", cookies).StatusCode != http.StatusSeeOther {
		t.Error("the pages are still open after logging out")
	}
}

// Password guessing must hit a limit.
func TestGuessingHitsTheLimit(t *testing.T) {
	s, _ := newServer(t)
	h := s.Handler()

	req := httptest.NewRequest("GET", "/login", nil)
	resp := httptest.NewRecorder()
	h.ServeHTTP(resp, req)
	cookies := resp.Result().Cookies()
	csrf := cookies[0].Value

	limited := false
	for i := 0; i < 15; i++ {
		form := url.Values{"name": {"owner"}, "password": {"guessing"}, "csrf": {csrf}}
		req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "203.0.113.7:12345"
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp := httptest.NewRecorder()
		h.ServeHTTP(resp, req)
		if resp.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Error("fifteen attempts in a row hit nothing")
	}
}

// The filters on the events page are what one goes through them by hand
// with.
func TestFiltersOnTheEventsPage(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	resp := get(t, s, "/events?decision=block", cookies)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "198.51.100.9") {
		t.Error("the filtered event disappeared")
	}
	if strings.Contains(string(body), "203.0.113.1") {
		t.Error("the decision filter did not work: a passed request is visible")
	}
}

// The write paths of the admin UI are the named POST handlers and
// nothing else: no page accepts a write of its own.
func TestNoWritesBesideTheNamedPaths(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	for _, path := range []string{"/", "/rules", "/events", "/domains"} {
		for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
			req := httptest.NewRequest(method, path, nil)
			for _, c := range cookies {
				req.AddCookie(c)
			}
			resp := httptest.NewRecorder()
			s.Handler().ServeHTTP(resp, req)
			if resp.Code != http.StatusMethodNotAllowed && resp.Code != http.StatusNotFound {
				t.Errorf("%s %s returned %d — there must be no second write path",
					method, path, resp.Code)
			}
		}
	}
}

func toggle(t *testing.T, s *Server, cookies []*http.Cookie, id string, enable bool, csrf string) int {
	t.Helper()
	value := "no"
	if enable {
		value = "yes"
	}
	form := url.Values{"id": {id}, "enable": {value}}
	if csrf != "" {
		form.Set("csrf", csrf)
	}
	req := httptest.NewRequest("POST", "/rules/toggle", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp.Code
}

func tokenFrom(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			return c.Value
		}
	}
	return ""
}

// A rule that is cutting off live people gets turned off in the minute it
// is noticed. The change goes into the file — by the same path as
// `antibot rules`.
func TestDisablingAndEnablingFromTheAdminUI(t *testing.T) {
	s, dir := newServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	if code := toggle(t, s, cookies, "block-curl", false, csrf); code != http.StatusSeeOther {
		t.Fatalf("disabling returned %d", code)
	}

	// It takes effect immediately: the in-memory set is already without
	// the rule.
	for _, rule := range s.o.Rules.Set().Effective() {
		if rule.ID == "block-curl" {
			t.Error("the disabled rule stayed in the effective set")
		}
	}

	// And it is written to the file: a restart of the node brings nothing
	// back.
	list, err := rules.Read(filepath.Join(dir, "rules.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Enabled == nil || *list[0].Enabled {
		t.Errorf("the rule is not disabled in the file: %+v", list)
	}

	if code := toggle(t, s, cookies, "block-curl", true, csrf); code != http.StatusSeeOther {
		t.Fatalf("enabling returned %d", code)
	}
	if len(s.o.Rules.Set().Effective()) != 1 {
		t.Error("the enabled rule did not come back into the set")
	}
}

func TestTogglingWithoutALoginAndWithoutAToken(t *testing.T) {
	s, dir := newServer(t)
	cookies := logIn(t, s)

	if code := toggle(t, s, nil, "block-curl", false, "from nowhere"); code != http.StatusSeeOther {
		t.Errorf("without a login the toggle returned %d, want a redirect to the login", code)
	}
	if code := toggle(t, s, cookies, "block-curl", false, ""); code != http.StatusForbidden {
		t.Errorf("without a token the toggle returned %d, want 403", code)
	}

	list, _ := rules.Read(filepath.Join(dir, "rules.json"))
	if len(list) == 1 && list[0].Enabled != nil && !*list[0].Enabled {
		t.Error("the rule got disabled after all")
	}
}

// A non-existent rule yields a message, not silence and not a panic.
func TestTogglingANonExistentRule(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)
	if code := toggle(t, s, cookies, "made up", false, tokenFrom(cookies)); code != http.StatusSeeOther {
		t.Errorf("got %d", code)
	}
	resp := get(t, s, "/rules?error="+url.QueryEscape(`there is no rule "made up"`), cookies)
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "there is no rule") {
		t.Error("the error was not shown to the human")
	}
}

func TestSecurityHeaders(t *testing.T) {
	s, _ := newServer(t)
	resp := get(t, s, "/login", nil)

	want := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for name, value := range want {
		if got := resp.Header.Get(name); got != value {
			t.Errorf("%s: %q, want %q", name, got, value)
		}
	}
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("the CSP is weaker than expected: %q", csp)
	}
}

// Without accounts the admin UI does not come up: "without a password for
// now" lasts years.
func TestWithoutAccountsItDoesNotComeUp(t *testing.T) {
	users, err := OpenUsers(filepath.Join(t.TempDir(), "admin.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Options{Addr: "127.0.0.1:8090", Users: users}); err == nil {
		t.Error("the admin UI came up without accounts")
	}
}

// A password travelling the network in clear text is access already
// granted.
func TestNonLoopbackWithoutACertificateIsARefusal(t *testing.T) {
	dir := t.TempDir()
	users, _ := OpenUsers(filepath.Join(dir, "admin.json"))
	if err := users.Set("owner", password); err != nil {
		t.Fatal(err)
	}

	refused := []string{"0.0.0.0:8090", "203.0.113.7:8090", ":8090"}
	for _, addr := range refused {
		if _, err := New(Options{Addr: addr, Users: users, EventsDir: dir}); err == nil {
			t.Errorf("the admin UI came up on %s without a certificate", addr)
		}
	}

	allowed := []string{"127.0.0.1:8090", "[::1]:8090", "localhost:8090"}
	for _, addr := range allowed {
		if _, err := New(Options{Addr: addr, Users: users, EventsDir: dir}); err != nil {
			t.Errorf("the admin UI did not come up on %s: %v", addr, err)
		}
	}
}

// An empty log is the ordinary state of a node that has just been
// installed.
func TestItOpensOnAnEmptyLog(t *testing.T) {
	dir := t.TempDir()
	users, _ := OpenUsers(filepath.Join(dir, "admin.json"))
	if err := users.Set("owner", password); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{
		Addr: "127.0.0.1:0", Users: users, Sessions: NewSessions(time.Hour),
		EventsDir: filepath.Join(dir, "no-such-dir"),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookies := logIn(t, s)
	for _, path := range []string{"/", "/events", "/rules"} {
		if resp := get(t, s, path, cookies); resp.StatusCode != http.StatusOK {
			t.Errorf("%s on an empty log returned %d", path, resp.StatusCode)
		}
	}
}

// The CSP allows styles only from the stylesheet, and a browser drops a
// style attribute without a word. The first overview drew its bars with
// style="height: …" and showed an empty box for it.
func TestPagesHaveNoInlineStyles(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)
	for _, path := range []string{"/", "/events", "/rules", "/?period=1h", "/?period=168h"} {
		body, _ := io.ReadAll(get(t, s, path, cookies).Body)
		if strings.Contains(string(body), "style=") {
			t.Errorf("%s carries a style attribute, which the CSP forbids", path)
		}
	}
}

func TestOverviewDrawsTheAnswers(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	body, _ := io.ReadAll(get(t, s, "/", cookies).Body)
	page := string(body)
	for _, piece := range []string{
		`class="donut"`, `class="columns"`,
		"2xx from the site", "not let through by the node",
		`/events?status=5xx`, `/events?status=blocked`,
		"2.0 KB", "30 ms",
	} {
		if !strings.Contains(page, piece) {
			t.Errorf("the overview does not contain %q", piece)
		}
	}
}

func TestEventsByStatus(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	body, _ := io.ReadAll(get(t, s, "/events?status=blocked", cookies).Body)
	if !strings.Contains(string(body), "198.51.100.9") || strings.Contains(string(body), "203.0.113.1") {
		t.Errorf("status=blocked did not select exactly the blocked request")
	}
}

// The tallest column must end at the top of the plot and not above it,
// whatever the numbers.
func TestColumnsStayInsideThePlot(t *testing.T) {
	t0 := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	var points []summary.Point
	for i, n := range []int{0, 7, 1234, 3, 999} {
		p := summary.Point{Time: t0.Add(time.Duration(i) * time.Hour), Events: n}
		p.Answers[summary.AnswerOK] = n - n/3
		p.Answers[summary.AnswerBlocked] = n / 3
		points = append(points, p)
	}
	chart := newColumns(points, 5*time.Hour)
	if chart == nil {
		t.Fatal("no chart")
	}
	if got := chart.Grid[len(chart.Grid)-1].Label; got != "1,500" {
		t.Errorf("the top tick reads %s, want a round 1,500", got)
	}
	if len(chart.Columns[0].Segments) != 0 {
		t.Errorf("an empty bucket has %d segments", len(chart.Columns[0].Segments))
	}
	for i, col := range chart.Columns {
		for _, seg := range col.Segments {
			var x, y float64
			fmt.Sscanf(seg.D, "M%f %f", &x, &y)
			if y > plotBase+0.01 {
				t.Errorf("column %d starts below the baseline: %s", i, seg.D)
			}
		}
	}
	if newColumns(make([]summary.Point, 5), time.Hour) != nil {
		t.Error("a chart was drawn over no requests")
	}
}
