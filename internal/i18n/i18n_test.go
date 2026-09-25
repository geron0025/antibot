package i18n

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func catalogOf(t *testing.T, files map[string]string) *Catalog {
	t.Helper()
	c, err := Load(mapFS(files), EN)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return c
}

func mapFS(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, contents := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(contents)}
	}
	return fsys
}

func TestMessagesOfEachLanguage(t *testing.T) {
	c := catalogOf(t, map[string]string{
		"en.json": `{"greeting": "Hello", "part": "{1} out of {0}"}`,
		"ru.json": `{"greeting": "Привет", "part": "{1} из {0}"}`,
	})
	if got := c.Printer(EN).T("greeting"); got != "Hello" {
		t.Errorf("en: %q", got)
	}
	if got := c.Printer(RU).T("greeting"); got != "Привет" {
		t.Errorf("ru: %q", got)
	}
	if got := c.Printer(RU).T("part", 3, 5); got != "5 из 3" {
		t.Errorf("arguments: %q", got)
	}
	if got := c.Printer(RU).T("part", 3000, "x"); got != "x из 3 000" {
		t.Errorf("an integer argument is a number of the language: %q", got)
	}
	if got := c.Printer(Lang("de")).Lang(); got != EN {
		t.Errorf("a language the catalog lacks gets the source one, got %q", got)
	}
	if got := c.Langs(); len(got) != 2 || got[0] != EN || got[1] != RU {
		t.Errorf("languages: %v", got)
	}
	if got := strings.Join(c.Keys(), ","); got != "greeting,part" {
		t.Errorf("keys: %q", got)
	}
}

func TestAMissingKeyShowsItself(t *testing.T) {
	c := catalogOf(t, map[string]string{"en.json": `{"a": "A"}`})
	if got := c.Printer(EN).T("nope"); got != "nope" {
		t.Errorf("T: %q", got)
	}
	if got := c.Printer(EN).N("nope", 3); got != "nope" {
		t.Errorf("N: %q", got)
	}
}

func TestPluralForms(t *testing.T) {
	c := catalogOf(t, map[string]string{
		"en.json": `{"days": {"one": "{0} day in {1}", "other": "{0} days in {1}"}}`,
		"ru.json": `{"days": {"one": "{0} день в {1}", "few": "{0} дня в {1}", "many": "{0} дней в {1}"}}`,
	})
	ru := map[int]string{
		0: "0 дней", 1: "1 день", 2: "2 дня", 4: "4 дня", 5: "5 дней",
		11: "11 дней", 12: "12 дней", 14: "14 дней", 21: "21 день",
		22: "22 дня", 25: "25 дней", 101: "101 день", 111: "111 дней",
		1001: "1 001 день",
	}
	for n, want := range ru {
		if got := c.Printer(RU).N("days", n, "x"); got != want+" в x" {
			t.Errorf("ru %d: %q, want %q", n, got, want+" в x")
		}
	}
	en := map[int]string{0: "0 days", 1: "1 day", 2: "2 days", 21: "21 days", 1000: "1,000 days"}
	for n, want := range en {
		if got := c.Printer(EN).N("days", n, "x"); got != want+" in x" {
			t.Errorf("en %d: %q, want %q", n, got, want+" in x")
		}
	}
}

func TestLoadRefusesABrokenCatalog(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // a piece of the error
	}{
		{"a key missing from a translation", map[string]string{
			"en.json": `{"a": "A", "b": "B"}`,
			"ru.json": `{"a": "А"}`,
		}, `"b"`},
		{"a key the source lacks", map[string]string{
			"en.json": `{"a": "A"}`,
			"ru.json": `{"a": "А", "c": "В"}`,
		}, `"c"`},
		{"a plural form missing", map[string]string{
			"en.json": `{"d": {"one": "{0} day", "other": "{0} days"}}`,
			"ru.json": `{"d": {"one": "{0} день", "many": "{0} дней"}}`,
		}, "few"},
		{"a form the language does not have", map[string]string{
			"en.json": `{"d": {"one": "{0} day", "few": "{0} days", "other": "{0} days"}}`,
		}, "few"},
		{"plural in one language only", map[string]string{
			"en.json": `{"d": {"one": "{0} day", "other": "{0} days"}}`,
			"ru.json": `{"d": "{0} дней"}`,
		}, `"d"`},
		{"an argument the source does not pass", map[string]string{
			"en.json": `{"a": "A {0}"}`,
			"ru.json": `{"a": "А {0} {1}"}`,
		}, "{1}"},
		{"an argument lost in translation", map[string]string{
			"en.json": `{"a": "A {0} {1}"}`,
			"ru.json": `{"a": "А {0}"}`,
		}, "{1}"},
		{"an unknown language", map[string]string{
			"en.json": `{"a": "A"}`,
			"de.json": `{"a": "A"}`,
		}, "de"},
		{"no source language", map[string]string{
			"ru.json": `{"a": "А"}`,
		}, "en"},
		{"not JSON", map[string]string{
			"en.json": `{"a": `,
		}, "en.json"},
		{"a value that is neither", map[string]string{
			"en.json": `{"a": 5}`,
		}, `"a"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(mapFS(tc.files), EN)
			if err == nil {
				t.Fatal("loaded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the error %q does not name %s", err, tc.want)
			}
		})
	}
}

func TestLoadSkipsOtherFiles(t *testing.T) {
	c := catalogOf(t, map[string]string{
		"en.json":   `{"a": "A"}`,
		"README.md": "not a catalog",
	})
	if got := c.Printer(EN).T("a"); got != "A" {
		t.Errorf("%q", got)
	}
}

func TestParse(t *testing.T) {
	for in, want := range map[string]Lang{"en": EN, "ru": RU} {
		if got, ok := Parse(in); !ok || got != want {
			t.Errorf("Parse(%q) = %q, %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "de", "RU", "ru-RU", "xx"} {
		if _, ok := Parse(in); ok {
			t.Errorf("Parse(%q) accepted", in)
		}
	}
}

func TestMatch(t *testing.T) {
	cases := map[string]Lang{
		"ru-RU,ru;q=0.9,en;q=0.8":      RU,
		"en-US,en;q=0.9":               EN,
		"fr, ru;q=0.1":                 RU,
		"en;q=0.2, RU;q=0.8":           RU,
		"ru;q=0, en":                   EN,
		"de-DE, fr;q=0.9":              "fallback",
		"*":                            "fallback",
		"":                             "fallback",
		"ru;q=nonsense, en;q=0.5":      EN,
		";;;,,,":                       "fallback",
		"ru-Cyrl-RU;q=0.7, en-GB;q=.6": RU,
	}
	for header, want := range cases {
		if got := Match(header, "fallback"); got != want {
			t.Errorf("Match(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestFormats(t *testing.T) {
	c := catalogOf(t, map[string]string{"en.json": `{}`, "ru.json": `{}`})
	en, ru := c.Printer(EN), c.Printer(RU)
	moment := time.Date(2026, 9, 5, 15, 4, 5, 0, time.Local)

	checks := []struct{ name, got, want string }{
		{"en number", en.Number(1234567), "1,234,567"},
		{"ru number", ru.Number(1234567), "1 234 567"},
		{"en small", en.Number(999), "999"},
		{"en negative", en.Number(-1234), "-1,234"},
		{"ru negative", ru.Number(-1234), "-1 234"},
		{"en decimal", en.Decimal(1.25, 1), "1.2"},
		{"ru decimal", ru.Decimal(1.5, 1), "1,5"},
		{"en percent", en.Percent(1, 8), "12.5%"},
		{"ru percent", ru.Percent(1, 8), "12,5 %"},
		{"en zero whole", en.Percent(3, 0), "0%"},
		{"ru zero whole", ru.Percent(3, 0), "0 %"},
		{"en time", en.Time(moment), "09/05 15:04:05"},
		{"ru time", ru.Time(moment), "05.09 15:04:05"},
		{"en date", en.Date(moment), "09/05/2026"},
		{"ru date", ru.Date(moment), "05.09.2026"},
		{"en short", en.Short(moment), "09/05 15:04"},
		{"ru short", ru.Short(moment), "05.09 15:04"},
		{"zero time", ru.Time(time.Time{}), "—"},
		{"zero date", en.Date(time.Time{}), "—"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s: %q, want %q", c.name, c.got, c.want)
		}
	}
}
