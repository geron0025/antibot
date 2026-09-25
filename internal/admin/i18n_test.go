package admin

import (
	"context"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/i18n"
)

func getAs(t *testing.T, s *Server, path string, cookies []*http.Cookie, acceptLanguage string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func withLang(cookies []*http.Cookie, lang string) []*http.Cookie {
	return append(append([]*http.Cookie{}, cookies...), &http.Cookie{Name: langCookieName, Value: lang})
}

func csrfOf(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == csrfCookieName {
			return c.Value
		}
	}
	return ""
}

// The viewer's choice first, then the browser, then admin.yaml.
func TestTheLanguageOfAPage(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	cases := []struct {
		name     string
		cookies  []*http.Cookie
		accept   string
		fallback i18n.Lang
		want     string
	}{
		{"nothing said", cookies, "", "", "en"},
		{"the cookie", withLang(cookies, "ru"), "en-US", "", "ru"},
		{"the browser", cookies, "ru-RU,ru;q=0.9,en;q=0.8", "", "ru"},
		{"admin.yaml", cookies, "", i18n.RU, "ru"},
		{"a browser language the admin UI lacks", cookies, "de-DE", i18n.RU, "ru"},
		{"a cookie of nonsense", withLang(cookies, "xx"), "ru", "", "ru"},
		{"the cookie beats admin.yaml", withLang(cookies, "en"), "", i18n.RU, "en"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.o.Language = tc.fallback
			code, body := getAs(t, s, "/rules", tc.cookies, tc.accept)
			if code != http.StatusOK {
				t.Fatalf("%d", code)
			}
			if !strings.Contains(body, `<html lang="`+tc.want+`">`) {
				t.Errorf("not in %s: %.300s", tc.want, body)
			}
			nav := map[string]string{"en": ">Rules</a>", "ru": ">Правила</a>"}[tc.want]
			if !strings.Contains(body, nav) {
				t.Errorf("the menu is not in %s", tc.want)
			}
		})
	}
}

func TestAdminConfigLanguage(t *testing.T) {
	write := func(t *testing.T, contents string) string {
		path := filepath.Join(t.TempDir(), "admin.yaml")
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg, err := LoadConfig(write(t, "language: ru\n"))
	if err != nil || cfg.Language != "ru" {
		t.Fatalf("%q %v", cfg.Language, err)
	}
	if _, err := LoadConfig(write(t, "language: de\n")); err == nil || !strings.Contains(err.Error(), "language") {
		t.Fatalf("an unknown language: %v", err)
	}
	if cfg := DefaultConfig(); cfg.Language != "en" {
		t.Fatalf("the default is %q", cfg.Language)
	}
}

func TestSwitchingTheLanguage(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)
	csrf := csrfOf(cookies)

	post := func(form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
		return postForm(t, s, "/language", cookies, form)
	}

	rec := post(url.Values{"csrf": {csrf}, "lang": {"ru"}, "back": {"/rules?period=1h"}}, cookies)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/rules?period=1h" {
		t.Fatalf("%d %v", rec.Code, rec.Header())
	}
	var set *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == langCookieName {
			set = c
		}
	}
	if set == nil || set.Value != "ru" || set.MaxAge < 300*24*3600 || !set.HttpOnly {
		t.Fatalf("the cookie: %+v", set)
	}

	for _, back := range []string{"//evil.example/", "https://evil.example/", "/\\evil.example", "", "rules"} {
		rec := post(url.Values{"csrf": {csrf}, "lang": {"en"}, "back": {back}}, cookies)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Errorf("back %q: %d %q", back, rec.Code, rec.Header().Get("Location"))
		}
	}

	if rec := post(url.Values{"lang": {"ru"}, "back": {"/"}}, cookies); rec.Code != http.StatusForbidden {
		t.Errorf("without the token: %d", rec.Code)
	}
	if rec := post(url.Values{"csrf": {csrf}, "lang": {"de"}, "back": {"/"}}, cookies); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown language: %d", rec.Code)
	}

	// The login page switches too: it has a token, and no session.
	req := httptest.NewRequest("GET", "/login", nil)
	login := httptest.NewRecorder()
	s.Handler().ServeHTTP(login, req)
	anonymous := login.Result().Cookies()
	if !strings.Contains(login.Body.String(), `action="/language"`) {
		t.Error("the login page has no switch")
	}
	rec = post(url.Values{"csrf": {csrfOf(anonymous)}, "lang": {"ru"}, "back": {"/login"}}, anonymous)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("from the login page: %d %v", rec.Code, rec.Header())
	}

	// The switch is in the account menu and says where it came from.
	_, body := getAs(t, s, "/rules?period=1h", cookies, "")
	if !strings.Contains(body, `action="/language"`) || !strings.Contains(body, `name="back" value="/rules?period=1h"`) {
		t.Error("the page has no switch, or it does not return here")
	}
}

// Every page, in Russian, all the way through.
func TestEveryPageSpeaksRussian(t *testing.T) {
	type page struct{ path, title string }
	check := func(t *testing.T, s *Server, pages []page) {
		cookies := withLang(logIn(t, s), "ru")
		for _, p := range pages {
			code, body := getAs(t, s, p.path, cookies, "")
			if code != http.StatusOK {
				t.Errorf("%s: %d", p.path, code)
				continue
			}
			for _, want := range []string{`<html lang="ru">`, "<title>" + p.title + " — antibot</title>", ">Обзор</a>", "Выйти"} {
				if !strings.Contains(body, want) {
					t.Errorf("%s does not contain %q", p.path, want)
				}
			}
			for _, english := range []string{">Overview</a>", "Log out", "for the last", "Settings</a>"} {
				if strings.Contains(body, english) {
					t.Errorf("%s still says %q", p.path, english)
				}
			}
		}
	}

	s, _ := newAlertsServer(t, "")
	check(t, s, []page{
		{"/", "Обзор"}, {"/events", "События"}, {"/rules", "Правила"},
		{"/rule?id=block-curl", "Правила"}, {"/alerts", "Оповещения"},
		{"/settings", "Настройки"}, {"/settings/core", "Настройки"},
		{"/settings/alerts", "Настройки"},
	})
	domains, _ := newDomainsServer(t)
	check(t, domains, []page{{"/domains", "Домены"}})
	tokens, _, _ := newAPIServer(t)
	check(t, tokens, []page{{"/settings/tokens", "Настройки"}})
	cloud := withCloud(t, &CloudState{Answered: true}, &fakeControl{})
	check(t, cloud, []page{{"/settings/cloud", "Настройки"}})

	code, body := getAs(t, s, "/login", nil, "ru")
	if code != http.StatusOK || !strings.Contains(body, `<html lang="ru">`) || !strings.Contains(body, "Войти") {
		t.Errorf("the login page: %d %.400s", code, body)
	}
}

// A message assembled in Go speaks the viewer's language; the error of
// the code inside it stays as the code wrote it.
func TestAFormRefusalSpeaksRussian(t *testing.T) {
	s, _, _ := newAPIServer(t)
	cookies := withLang(logIn(t, s), "ru")
	rec := postForm(t, s, "/settings/tokens/issue", cookies, url.Values{
		"csrf": {csrfOf(cookies)}, "name": {"x"}, "scope": {"read"}, "days": {"30"},
		"password": {"not the password"},
	})
	location, _ := url.QueryUnescape(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || !strings.Contains(location, "Пароль не подошёл") {
		t.Fatalf("%d %q", rec.Code, location)
	}

	rec = postForm(t, s, "/settings/tokens/issue", cookies, url.Values{"name": {"x"}})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "не с этой страницы") {
		t.Fatalf("a forged form: %d %q", rec.Code, rec.Body)
	}
}

// oldCore is a core from before the thresholds came as numbers.
type oldCore struct{ control.Core }

func (c oldCore) Alerts(ctx context.Context) (control.Alerts, error) {
	a, err := c.Core.Alerts(ctx)
	for i := range a.Triggers {
		a.Triggers[i].Args = nil
	}
	return a, err
}

func TestTriggerConditionsSpeakRussian(t *testing.T) {
	s, _ := newAlertsServer(t, "")
	cookies := withLang(logIn(t, s), "ru")

	_, body := getAs(t, s, "/alerts", cookies, "")
	for _, want := range []string{"сайт не отвечает", "5xx сайта в 50 % из не менее чем 20 дошедших до него запросов за 5 мин",
		"диск кончается"} {
		if !strings.Contains(body, want) {
			t.Errorf("the alerts page does not contain %q", want)
		}
	}

	s.o.Core = oldCore{s.o.Core}
	_, body = getAs(t, s, "/alerts", cookies, "")
	if !strings.Contains(body, "a 5xx of the site in 50% of at least 20 requests that reached it, over 5m") {
		t.Error("without the numbers the core's own words are not shown")
	}
	if !strings.Contains(body, "сайт не отвечает") {
		t.Error("the title does not need the numbers")
	}
}

// --- the guards ---

var (
	actionPattern  = regexp.MustCompile(`(?s)\{\{.*?\}\}`)
	attrPattern    = regexp.MustCompile(`(?i)\b(placeholder|title|aria-label|alt)="([^"]*)"`)
	tagPattern     = regexp.MustCompile(`(?s)<[^>]*>`)
	entityPattern  = regexp.MustCompile(`&[a-zA-Z]+;|&#\d+;`)
	wordPattern    = regexp.MustCompile(`\p{L}[\p{L}\d'-]*`)
	templateKey    = regexp.MustCompile(`\b(t|tn) "([^"]+)"`)
	goCallKey      = regexp.MustCompile(`\.(T|N|t|n)\((?:r, )?"([^"]+)"`)
	goLiteral      = regexp.MustCompile(`"([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)"`)
	notAKeySuffix  = regexp.MustCompile(`\.(json|yaml|html|css|pem|sock|md)$`)
	bareTextAllows = map[string]bool{"antibot": true}
)

// Every word a human reads in a template comes through the catalog: a
// word written into the markup is a word that stays English on a Russian
// page.
func TestTemplatesHaveNoBareText(t *testing.T) {
	files, _ := fs.Glob(templatesFS, "templates/*.html")
	for _, name := range files {
		raw, _ := templatesFS.ReadFile(name)
		text := actionPattern.ReplaceAllString(string(raw), "")
		for _, m := range attrPattern.FindAllStringSubmatch(text, -1) {
			if wordPattern.MatchString(m[2]) {
				t.Errorf("%s: %s=%q is not translated", name, m[1], m[2])
			}
		}
		text = tagPattern.ReplaceAllString(text, " ")
		text = entityPattern.ReplaceAllString(text, " ")
		for _, word := range wordPattern.FindAllString(text, -1) {
			if !bareTextAllows[word] {
				t.Errorf("%s: %q is written into the markup", name, word)
			}
		}
	}
}

// rawCatalog reads a catalog file as it lies: which keys are plural.
func rawCatalog(t *testing.T, lang string) map[string]json.RawMessage {
	t.Helper()
	contents, err := localesFS.ReadFile("locales/" + lang + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(contents, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every key the code names is in the catalog, and every key of the
// catalog is named somewhere: a translation nobody shows is a translation
// nobody keeps up to date.
func TestCatalogKeysAreUsedAndPresent(t *testing.T) {
	catalog := rawCatalog(t, "en")
	plural := func(key string) bool { return strings.HasPrefix(string(catalog[key]), "{") }

	named := map[string]bool{}
	var sources []string

	files, _ := fs.Glob(templatesFS, "templates/*.html")
	for _, name := range files {
		raw, _ := templatesFS.ReadFile(name)
		sources = append(sources, string(raw))
		for _, m := range templateKey.FindAllStringSubmatch(string(raw), -1) {
			named[m[2]] = true
			if _, ok := catalog[m[2]]; ok && (m[1] == "tn") != plural(m[2]) {
				t.Errorf("%s: %s %q, and the key is %s", name, m[1], m[2], map[bool]string{true: "plural", false: "not plural"}[plural(m[2])])
			}
		}
	}
	goFiles, _ := filepath.Glob("*.go")
	for _, name := range goFiles {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(name)
		sources = append(sources, string(raw))
		for _, m := range goCallKey.FindAllStringSubmatch(string(raw), -1) {
			named[m[2]] = true
		}
		for _, m := range goLiteral.FindAllStringSubmatch(string(raw), -1) {
			if !notAKeySuffix.MatchString(m[1]) {
				named[m[1]] = true
			}
		}
	}

	var missing []string
	for key := range named {
		if _, ok := catalog[key]; !ok {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	for _, key := range missing {
		t.Errorf("%q is named in the code and is not in the catalog", key)
	}

	all := strings.Join(sources, "\n")
	for key := range catalog {
		if !strings.Contains(all, `"`+key+`"`) {
			t.Errorf("%q is in the catalog and nothing shows it", key)
		}
	}
}

var markupPattern = regexp.MustCompile(`<[a-zA-Z/]`)

// Markup lives only in the keys that say so; everything else is text,
// escaped by the template like any other. "<1 ms" is text: a tag is a
// bracket and a name.
func TestMarkupOnlyInHTMLKeys(t *testing.T) {
	for _, lang := range []string{"en", "ru"} {
		for key, value := range rawCatalog(t, lang) {
			if !strings.HasSuffix(key, "_html") && markupPattern.Match(value) {
				t.Errorf("%s %q carries markup and is not an _html key", lang, key)
			}
		}
	}

	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	p := c.Printer(i18n.EN)
	if got, ok := localize(p, "login.accounts_html").(template.HTML); !ok || !strings.Contains(string(got), "<code>") {
		t.Errorf("an _html key is not HTML: %#v", got)
	}
	if got, ok := localize(p, "login.title").(string); !ok || got != "Log in" {
		t.Errorf("a plain key is not text: %#v", got)
	}
	// An argument of an _html key is text, however it looks.
	got := localize(p, "overview.cert_expired_html", "<b>7</b>", "<i>")
	if s := string(got.(template.HTML)); strings.Contains(s, "<b>7") || !strings.Contains(s, "&lt;b&gt;7") || !strings.Contains(s, "&lt;i&gt;") {
		t.Errorf("an argument was not escaped: %s", s)
	}
}

func TestTheCatalogLoads(t *testing.T) {
	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Langs(); len(got) != 2 {
		t.Fatalf("languages: %v", got)
	}
}

// english is the source language's printer, for the parts of the pages
// tested apart from a request.
func english(t *testing.T) *i18n.Printer {
	t.Helper()
	c, err := loadCatalog()
	if err != nil {
		t.Fatal(err)
	}
	return c.Printer(i18n.EN)
}
