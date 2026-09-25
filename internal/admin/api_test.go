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

	"github.com/geron0025/antibot/internal/alerts"
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

	// The page is a tab of the settings; its old address still leads there.
	if rec := call(t, s, "GET", "/tokens", "", "", cookies...); rec.Code != http.StatusMovedPermanently ||
		rec.Header().Get("Location") != "/settings/tokens" {
		t.Fatalf("/tokens: %d to %q", rec.Code, rec.Header().Get("Location"))
	}
	page := call(t, s, "GET", "/settings/tokens", "", "", cookies...)
	for _, want := range []string{"monitoring", "ci", "Issue a token",
		`href="/settings" class="current">Settings</a>`, `href="/settings/tokens" class="current"`} {
		if !strings.Contains(page.Body.String(), want) {
			t.Errorf("the page does not contain %q", want)
		}
	}

	issue := url.Values{"csrf": {csrf}, "name": {"panel"}, "scope": {"read"}, "days": {"30"},
		"password": {"not the password at all"}}
	if rec := post("/settings/tokens/issue", issue); rec.Code != http.StatusSeeOther ||
		!strings.Contains(rec.Header().Get("Location"), "error") {
		t.Fatalf("a wrong password: %d %v", rec.Code, rec.Header())
	}
	if list, _ := s.o.Tokens.List(); len(list) != 2 {
		t.Fatal("a token was issued against a wrong password")
	}

	noCSRF := url.Values{"name": {"panel"}, "scope": {"read"}, "days": {"30"}, "password": {password}}
	if rec := post("/settings/tokens/issue", noCSRF); rec.Code != http.StatusForbidden {
		t.Fatalf("without CSRF: %d", rec.Code)
	}

	issue.Set("password", password)
	rec := post("/settings/tokens/issue", issue)
	value := regexp.MustCompile(`abn_[A-Za-z0-9_-]{43}`).FindString(rec.Body.String())
	if rec.Code != http.StatusOK || value == "" {
		t.Fatalf("issue: %d %s", rec.Code, rec.Body)
	}
	if rec := call(t, s, "GET", "/api/v1/rules", value, ""); rec.Code != http.StatusOK {
		t.Fatalf("the issued token: %d", rec.Code)
	}

	if rec := post("/settings/tokens/revoke", url.Values{"csrf": {csrf}, "name": {"panel"}, "password": {password}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if rec := call(t, s, "GET", "/api/v1/rules", value, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("the revoked token: %d", rec.Code)
	}
	if strings.Contains(call(t, s, "GET", "/settings/tokens", "", "", cookies...).Body.String(), value) {
		t.Fatal("the page shows the value a second time")
	}
}

// A read token reads and a write token writes; every change goes through
// rules.Store, answers with the rule as it now is, and tells the caller's
// mistake from the node's trouble.
func TestAPIWritesRules(t *testing.T) {
	s, read, write := newAPIServer(t)
	rulesSchema := schema(t, "api-rules")
	change := rulesSchema["$defs"].(map[string]any)["change"].(map[string]any)
	errorSchema := schema(t, "api-error")

	draft := `{"id":"watch-python","scope":["*"],"mode":"shadow","priority":10,
		"condition":{"field":"ua","op":"contains","value":"python"},"action":{"type":"block"}}`

	if rec := call(t, s, "POST", "/api/v1/rules", read, draft); rec.Code != http.StatusForbidden {
		t.Fatalf("a read token added a rule: %d", rec.Code)
	}
	rec := call(t, s, "POST", "/api/v1/rules", write, draft)
	if rec.Code != http.StatusCreated {
		t.Fatalf("add: %d %s", rec.Code, rec.Body)
	}
	if errs := schemacheck.ValidateAt(rulesSchema, change, decode(t, rec), "$"); len(errs) > 0 {
		t.Fatal(errs)
	}

	for name, c := range map[string]struct {
		method, path, body string
		code               int
	}{
		"the same id again":          {"POST", "/api/v1/rules", draft, 409},
		"a typo in a field":          {"POST", "/api/v1/rules", strings.Replace(draft, `"priority"`, `"priorty"`, 1), 400},
		"a field rules do not know":  {"POST", "/api/v1/rules", strings.Replace(draft, `"ua"`, `"useragent"`, 1), 400},
		"not JSON":                   {"POST", "/api/v1/rules", "{", 400},
		"two values":                 {"POST", "/api/v1/rules", draft + draft, 400},
		"a mode that does not exist": {"POST", "/api/v1/rules/watch-python/mode", `{"mode":"loud"}`, 400},
		"a rule that is not there":   {"POST", "/api/v1/rules/nothing/enable", "", 404},
		"deleting what is not there": {"DELETE", "/api/v1/rules/nothing", "", 404},
	} {
		rec := call(t, s, c.method, c.path, write, c.body)
		if rec.Code != c.code {
			t.Errorf("%s: %d, want %d: %s", name, rec.Code, c.code, rec.Body)
			continue
		}
		if errs := schemacheck.Validate(errorSchema, decode(t, rec)); len(errs) > 0 {
			t.Errorf("%s: %v", name, errs)
		}
	}

	for _, step := range []struct{ path, body, want string }{
		{"/api/v1/rules/watch-python/disable", "", `"enabled":false`},
		{"/api/v1/rules/watch-python/enable", "", `"enabled":true`},
		{"/api/v1/rules/watch-python/mode", `{"mode":"active"}`, `"mode":"active"`},
	} {
		rec := call(t, s, "POST", step.path, write, step.body)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), step.want) {
			t.Errorf("%s: %d %s", step.path, rec.Code, rec.Body)
		}
	}
	if n := len(s.o.Rules.Set().Effective()); n != 2 {
		t.Fatalf("%d rules in force", n)
	}

	// Straight into active is allowed, and said out loud.
	active := strings.NewReplacer(`"watch-python"`, `"block-wget"`, `"shadow"`, `"active"`,
		`"python"`, `"Wget"`).Replace(draft)
	rec = call(t, s, "POST", "/api/v1/rules", write, active)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"warning"`) {
		t.Fatalf("straight into active: %d %s", rec.Code, rec.Body)
	}

	if rec := call(t, s, "DELETE", "/api/v1/rules/watch-python", write, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	list := call(t, s, "GET", "/api/v1/rules", read, "").Body.String()
	if !strings.Contains(list, "block-curl") || !strings.Contains(list, "block-wget") ||
		strings.Contains(list, "watch-python") {
		t.Fatalf("after the changes: %s", list)
	}
}

// The alerts page for a program: every trigger, what fires now, and the
// messages with their delivery — all as the schema says.
func TestAPIAlerts(t *testing.T) {
	s, read, _ := newAPIServer(t)
	if rec := call(t, s, "GET", "/api/v1/alerts", read, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("with the alerts off: %d %s", rec.Code, rec.Body)
	}

	local(s).Watcher = alerts.New(alerts.Options{
		Window: 5 * time.Minute, SiteErrorShare: 0.5, SiteMinRequests: 20, SpikeFactor: 5,
		SpikeMinRequests: 500, SpikeMinBlocked: 200, RuleMinMatches: 50, CertDays: 14,
		Timeout: time.Second,
	})
	now := time.Now()
	for i := 0; i < 30; i++ {
		local(s).Watcher.Write(facts.Request{Time: now.Add(-2 * time.Minute), Decision: "pass", Status: 502})
	}
	local(s).Watcher.Check(now)

	rec := call(t, s, "GET", "/api/v1/alerts", read, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if errs := schemacheck.Validate(schema(t, "api-alerts"), decode(t, rec)); len(errs) > 0 {
		t.Fatalf("%v\n%s", errs, rec.Body)
	}
	var answer struct {
		Triggers []struct {
			Kind   string `json:"kind"`
			Firing []struct {
				ID string `json:"id"`
			} `json:"firing"`
		} `json:"triggers"`
		History []struct {
			State    string `json:"state"`
			Delivery string `json:"delivery"`
		} `json:"history"`
	}
	json.Unmarshal(rec.Body.Bytes(), &answer)
	if len(answer.Triggers) != 9 || answer.Triggers[0].Kind != alerts.SiteDown ||
		len(answer.Triggers[0].Firing) != 1 || answer.Triggers[0].Firing[0].ID != alerts.SiteDown {
		t.Fatalf("%s", rec.Body)
	}
	if len(answer.History) != 1 || answer.History[0].State != alerts.Firing {
		t.Fatalf("%s", rec.Body)
	}
}

// A draft runs over the log together with the rules in force, and nothing
// is written: the answer says whom it would touch.
func TestAPIReplay(t *testing.T) {
	s, read, _ := newAPIServer(t)
	body := `{"rule":{"id":"block-googlebot-lookalikes","scope":["*"],"mode":"active","priority":200,
		"condition":{"field":"ua","op":"contains","value":"Googlebot"},"action":{"type":"block"}},
		"period":"1h","examples":1}`

	rec := call(t, s, "POST", "/api/v1/replay", read, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if errs := schemacheck.Validate(schema(t, "api-replay"), decode(t, rec)); len(errs) > 0 {
		t.Fatalf("%v\n%s", errs, rec.Body)
	}
	var answer struct {
		Events      int            `json:"events"`
		Divergences map[string]int `json:"divergences"`
		Rule        struct {
			Matched int             `json:"matched"`
			Samples []facts.Request `json:"samples"`
		} `json:"rule"`
	}
	json.Unmarshal(rec.Body.Bytes(), &answer)
	if answer.Events != 2 || answer.Rule.Matched != 1 || len(answer.Rule.Samples) != 1 ||
		answer.Rule.Samples[0].IP != "203.0.113.1" || len(answer.Divergences) == 0 {
		t.Fatalf("%s", rec.Body)
	}
	if n := len(s.o.Rules.Set().All()); n != 1 {
		t.Fatalf("the replay wrote the draft: %d rules", n)
	}

	for name, bad := range map[string]string{
		"a field rules do not know": strings.Replace(body, `"ua"`, `"useragent"`, 1),
		"no draft":                  `{"period":"1h"}`,
		"too many examples":         strings.Replace(body, `"examples":1`, `"examples":500`, 1),
		"a period it cannot read":   strings.Replace(body, `"1h"`, `"an hour"`, 1),
	} {
		if rec := call(t, s, "POST", "/api/v1/replay", read, bad); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
}
