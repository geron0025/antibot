package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/schemacheck"
)

// newAPIServer is the test admin UI with a tokens file and a token of
// each scope in it.
func newAPIServer(t *testing.T) (s *Server, read, write string) {
	t.Helper()
	s, dir := newServer(t)
	tokens, err := OpenTokens(filepath.Join(dir, "api-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.o.Tokens = tokens
	if read, _, err = tokens.Issue("monitoring", ScopeRead, 30, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if write, _, err = tokens.Issue("ci", ScopeWrite, 30, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	return s, read, write
}

func call(t *testing.T, s *Server, method, path, token, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) any {
	t.Helper()
	var doc any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, rec.Body)
	}
	return doc
}

func schema(t *testing.T, name string) map[string]any {
	t.Helper()
	s, err := schemacheck.Load(filepath.Join("..", "..", "docs", "schema", name+".schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A program comes with a token, and nothing else opens the API: not a
// session, not a cloud token, not a revoked one.
func TestAPINeedsAToken(t *testing.T) {
	s, read, _ := newAPIServer(t)
	cookies := logIn(t, s)

	for name, c := range map[string]struct {
		token   string
		cookies []*http.Cookie
	}{
		"nothing":          {},
		"a session cookie": {cookies: cookies},
		"an unknown token": {token: "abn_nonsense"},
		"a cloud token":    {token: "ab_" + read[len("abn_"):]},
	} {
		rec := call(t, s, "GET", "/api/v1/summary", c.token, "", c.cookies...)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" ||
			!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
			t.Errorf("%s: %d %v", name, rec.Code, rec.Header())
		}
	}

	// And a token does not open the pages.
	if rec := call(t, s, "GET", "/", read, ""); rec.Code != http.StatusSeeOther {
		t.Errorf("a token on a page: %d", rec.Code)
	}

	if err := s.o.Tokens.Revoke("monitoring", time.Now()); err != nil {
		t.Fatal(err)
	}
	if rec := call(t, s, "GET", "/api/v1/summary", read, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("a revoked token: %d", rec.Code)
	}
}

// Every answer is what its schema in docs/schema says, and the schemas
// are strict enough to notice a field they do not describe.
func TestAPIAnswersMatchTheSchemas(t *testing.T) {
	s, read, _ := newAPIServer(t)

	for _, c := range []struct {
		path, schema string
		code         int
	}{
		{"/api/v1/summary?period=1h", "api-summary", 200},
		{"/api/v1/events", "api-events", 200},
		{"/api/v1/events?limit=1", "api-events", 200},
		{"/api/v1/rules", "api-rules", 200},
		{"/api/v1/summary?period=forever", "api-error", 400},
		{"/api/v1/nowhere", "api-error", 404},
	} {
		rec := call(t, s, "GET", c.path, read, "")
		if rec.Code != c.code {
			t.Errorf("%s: %d, want %d: %s", c.path, rec.Code, c.code, rec.Body)
			continue
		}
		if errs := schemacheck.Validate(schema(t, c.schema), decode(t, rec)); len(errs) > 0 {
			t.Errorf("%s: %v\n%s", c.path, errs, rec.Body)
		}
	}

	doc := decode(t, call(t, s, "GET", "/api/v1/events", read, "")).(map[string]any)
	doc["events"].([]any)[0].(map[string]any)["cookie_value"] = "secret"
	if errs := schemacheck.Validate(schema(t, "api-events"), doc); len(errs) == 0 {
		t.Error("an event field the schema does not describe passed")
	}
}

// The pages go back in time: next_before of one is before of the next.
func TestAPIEventsPageByPage(t *testing.T) {
	s, read, _ := newAPIServer(t)

	var page struct {
		Events     []facts.Request `json:"events"`
		NextBefore string          `json:"next_before"`
	}
	var seen []string
	path := "/api/v1/events?limit=1"
	for i := 0; i < 5; i++ {
		rec := call(t, s, "GET", path, read, "")
		page.Events, page.NextBefore = nil, ""
		if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil {
			t.Fatal(err)
		}
		for _, e := range page.Events {
			seen = append(seen, e.IP)
		}
		if page.NextBefore == "" {
			break
		}
		path = "/api/v1/events?limit=1&before=" + url.QueryEscape(page.NextBefore)
	}
	if strings.Join(seen, " ") != "198.51.100.9 203.0.113.1" {
		t.Fatalf("pages gave %v", seen)
	}

	rec := call(t, s, "GET", "/api/v1/events?decision=block", read, "")
	json.Unmarshal(rec.Body.Bytes(), &page)
	if len(page.Events) != 1 || page.Events[0].Rule != "block-curl" {
		t.Fatalf("filter: %s", rec.Body)
	}
}

// A parameter the API cannot read is a 400, not a quiet default: a
// program must learn that it asked for something else than it got.
func TestAPIRefusesWhatItCannotRead(t *testing.T) {
	s, read, _ := newAPIServer(t)
	for _, path := range []string{
		"/api/v1/summary?period=abc", "/api/v1/summary?period=0s", "/api/v1/summary?period=2200h",
		"/api/v1/summary?top=0", "/api/v1/events?limit=0", "/api/v1/events?limit=5000",
		"/api/v1/events?before=yesterday", "/api/v1/rules?period=-1h",
	} {
		if rec := call(t, s, "GET", path, read, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

// The tokens page issues a token only against the password, shows its
// value once, and revokes it.
func TestTokensPage(t *testing.T) {
	s, _, _ := newAPIServer(t)
	cookies := logIn(t, s)
	var csrf string
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			csrf = c.Value
		}
	}
	post := func(path string, form url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}

	page := call(t, s, "GET", "/tokens", "", "", cookies...)
	for _, want := range []string{"monitoring", "ci", "Issue a token", "API tokens"} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("the page does not contain %q", want)
		}
	}

	issue := url.Values{"csrf": {csrf}, "name": {"panel"}, "scope": {"read"}, "days": {"30"},
		"password": {"not the password at all"}}
	if rec := post("/tokens/issue", issue); rec.Code != http.StatusSeeOther ||
		!strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("a wrong password: %d %v", rec.Code, rec.Header())
	}
	if list, _ := s.o.Tokens.List(); len(list) != 2 {
		t.Fatal("a token was issued against a wrong password")
	}

	noCSRF := url.Values{"name": {"panel"}, "scope": {"read"}, "days": {"30"}, "password": {password}}
	if rec := post("/tokens/issue", noCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", rec.Code)
	}

	issue.Set("password", password)
	rec := post("/tokens/issue", issue)
	value := regexp.MustCompile(`abn_[A-Za-z0-9_-]{43}`).FindString(rec.Body.String())
	if rec.Code != http.StatusOK || value == "" {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/rules", value, ""); rec.Code != http.StatusOK {
		t.Fatalf("the issued token: %d", rec.Code)
	}

	if rec := post("/tokens/revoke", url.Values{"csrf": {csrf}, "name": {"panel"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/rules", value, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the revoked token: %d", rec.Code)
	}
	if strings.Contains(call(t, s, "GET", "/tokens", "", "", cookies...).Body.String(), value) {
		t.Fatal("the page shows the value a second time")
	}
}
