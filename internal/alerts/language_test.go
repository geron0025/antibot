package alerts

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/i18n"
)

func speaking(lang i18n.Lang) Options {
	o := options()
	o.Language = func() i18n.Lang { return lang }
	return o
}

func TestTheAlertsCatalogLoads(t *testing.T) {
	c, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Langs(); len(got) != 2 {
		t.Fatalf("languages: %v", got)
	}
}

var keyLiteral = regexp.MustCompile(`"((?:alert|trigger|span)\.[a-z0-9_.]+)"`)

// Every key the code names is in the catalog, and nothing else is.
func TestAlertsCatalogKeysAreUsedAndPresent(t *testing.T) {
	c, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, k := range c.Keys() {
		known[k] = true
	}
	named := map[string]bool{}
	files, _ := filepath.Glob("*.go")
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(name)
		for _, m := range keyLiteral.FindAllStringSubmatch(string(raw), -1) {
			named[m[1]] = true
		}
	}
	for k := range named {
		if !known[k] {
			t.Errorf("%q is named in the code and is not in the catalog", k)
		}
	}
	for k := range known {
		if !named[k] {
			t.Errorf("%q is in the catalog and nothing names it", k)
		}
	}
}

// The same story as TestSiteDownFiresOnceAndResolvesOnce, told in
// Russian: the firing message, and the resolved one recalling it.
func TestMessagesInTheDeliveryLanguage(t *testing.T) {
	w := watcher(speaking(i18n.RU), start)
	for m := 0; m < 5; m++ {
		feed(w, m, 10, failed)
	}
	for m := 5; m < 30; m++ {
		feed(w, m, 10, served)
	}
	for m := 5; m <= 20; m++ {
		w.Check(at(m))
	}
	h := w.History()
	if len(h) != 2 {
		t.Fatalf("messages: %s", strings.Join(states(w), ", "))
	}
	fired, resolved := h[1], h[0]
	if !strings.Contains(fired.Text, "сайт отвечает ошибками: 50 из 50") || fired.Language != i18n.RU ||
		fired.Message.Key != "alert.site_down" {
		t.Fatalf("firing: %+v", fired.Alert)
	}
	for _, want := range []string{"пришло в норму: сайт не отвечает длилось 3 мин",
		"всё спокойно последние 5 мин", "Когда сработало: сайт отвечает ошибками: 50 из 50"} {
		if !strings.Contains(resolved.Text, want) {
			t.Errorf("the resolved message has no %q: %s", want, resolved.Text)
		}
	}
	// The admin UI words the same message in its viewer's language.
	if got := resolved.Message.In(i18n.EN); !strings.Contains(got, "back to normal: the site does not answer lasted 3m") ||
		!strings.Contains(got, "When it fired: the site answers with errors: 50 of 50 requests") {
		t.Errorf("in English: %s", got)
	}
}

// A message survives the trip over the control socket and is worded the
// same on the other side.
func TestAMessageSurvivesJSON(t *testing.T) {
	m := Message{Key: "alert.resolved", Args: []Arg{
		{Trigger: SiteDown}, seconds(3 * time.Minute), seconds(5 * time.Minute),
		{Message: &Message{Key: "alert.site_down", Args: []Arg{number(1234), number(5000), seconds(5 * time.Minute)}}},
	}}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var back Message
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	for _, lang := range []i18n.Lang{i18n.EN, i18n.RU} {
		if a, b := m.In(lang), back.In(lang); a != b || a == "" {
			t.Errorf("%s: %q became %q", lang, a, b)
		}
	}
	if got := back.In(i18n.RU); !strings.Contains(got, "1 234 из 5 000") {
		t.Errorf("the numbers are not Russian: %s", got)
	}
	if got := (Message{Key: "alert.nonexistent"}).In(i18n.RU); got != "alert.nonexistent" {
		t.Errorf("an unknown key: %q", got)
	}
}

// The language is read at every message: a change in the admin UI takes
// effect with the next one, without a restart.
func TestTheLanguageChangesOnTheFly(t *testing.T) {
	lang := i18n.EN
	o := options()
	o.Language = func() i18n.Lang { return lang }
	o.Command = func() string { return "cat > /dev/null" }
	w := watcher(o, start)

	w.Test(context.Background())
	lang = i18n.RU
	w.Test(context.Background())
	h := w.History()
	if !strings.HasPrefix(h[1].Text, "a test message from antibot") || !strings.HasPrefix(h[0].Text, "проверочное сообщение от antibot") {
		t.Fatalf("%q, then %q", h[1].Text, h[0].Text)
	}

	// Nothing said is English, and so is a language the node lacks.
	for _, f := range []func() i18n.Lang{nil, func() i18n.Lang { return "" }, func() i18n.Lang { return "de" }} {
		o.Language = f
		w := watcher(o, start)
		w.Test(context.Background())
		if h := w.History(); h[0].Language != i18n.EN || !strings.HasPrefix(h[0].Text, "a test message") {
			t.Errorf("%+v", h[0].Alert)
		}
	}
}

// The command gets the text in the delivery language, the language
// itself, and the message as a key and its arguments.
func TestTheCommandGetsTheLanguage(t *testing.T) {
	dir := t.TempDir()
	o := speaking(i18n.RU)
	o.Command = func() string {
		return `printf '%s|%s' "$ANTIBOT_ALERT_LANGUAGE" "$ANTIBOT_ALERT_TEXT" > "` + dir + `/env"; cat > "` + dir + `/stdin.json"`
	}
	w := watcher(o, start)
	w.Test(context.Background())

	env, _ := os.ReadFile(filepath.Join(dir, "env"))
	if !strings.HasPrefix(string(env), "ru|проверочное сообщение") {
		t.Fatalf("the environment: %q", env)
	}
	var got struct {
		Language string  `json:"language"`
		Text     string  `json:"text"`
		Message  Message `json:"message"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "stdin.json"))
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Language != "ru" || got.Message.Key != "alert.test" || !strings.HasPrefix(got.Text, "проверочное") {
		t.Fatalf("stdin: %s", raw)
	}
}

// What is firing now is worded in the delivery language too, and carries
// its message for the admin UI.
func TestFiringCarriesItsMessage(t *testing.T) {
	o := speaking(i18n.RU)
	o.Probes.Outbox = func() (int, bool) { return 20, true }
	w := watcher(o, start)
	w.Check(at(1))
	f := w.Firing()
	if len(f) != 1 || f[0].Message.Key != "alert.outbox_stuck" || !strings.Contains(f[0].Text, "20") ||
		!strings.Contains(f[0].Message.In(i18n.EN), "20 aggregate batches wait to be sent") {
		t.Fatalf("%+v", f)
	}
}

func TestTriggersInEitherLanguage(t *testing.T) {
	w := watcher(options(), start)
	var site Trigger
	for _, tr := range w.Triggers() {
		if tr.Kind == SiteDown {
			site = tr
		}
	}
	ru := site.In(i18n.RU)
	if ru.Title != "сайт не отвечает" ||
		ru.When != "5xx сайта в 50 % из не менее чем 20 дошедших до него запросов за 5 мин" {
		t.Fatalf("%+v", ru)
	}
	if en := site.In(i18n.EN); en.Title != site.Title || en.When != site.When {
		t.Errorf("English differs from the core's own words: %+v vs %+v", en, site)
	}
	// A core too old to send the numbers keeps its own condition.
	old := site
	old.Args = nil
	if got := old.In(i18n.RU); got.Title != "сайт не отвечает" || got.When != site.When {
		t.Errorf("%+v", got)
	}
}

func TestSpans(t *testing.T) {
	c, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	en, ru := c.Printer(i18n.EN), c.Printer(i18n.RU)
	cases := []struct {
		seconds int64
		en, ru  string
	}{
		{30, "under a minute", "меньше минуты"},
		{300, "5m", "5 мин"},
		{3600, "1h", "1 ч"},
		{3900, "1h05m", "1 ч 05 мин"},
		{86400, "24h", "24 ч"},
		{3 * 86400, "3 days", "3 дня"},
		{5 * 86400, "5 days", "5 дней"},
	}
	for _, tc := range cases {
		if got := Span(en, tc.seconds); got != tc.en {
			t.Errorf("en %d: %q, want %q", tc.seconds, got, tc.en)
		}
		if got := Span(ru, tc.seconds); got != tc.ru {
			t.Errorf("ru %d: %q, want %q", tc.seconds, got, tc.ru)
		}
		// The core's own English words agree with the catalog's.
		if got := span(time.Duration(tc.seconds) * time.Second); got != tc.en {
			t.Errorf("span %d: %q, want %q", tc.seconds, got, tc.en)
		}
	}
}

func TestTheCommandFileKeepsTheLanguage(t *testing.T) {
	f, err := OpenCommand(filepath.Join(t.TempDir(), "alerts.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Save("true", "ru", "owner", start); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.Get(); c.Command != "true" || c.Language != "ru" {
		t.Fatalf("%+v", c)
	}
	// Set changes the command and keeps the language.
	if err := f.Set("false", "owner", start); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.Get(); c.Command != "false" || c.Language != "ru" {
		t.Fatalf("after Set: %+v", c)
	}
	if err := f.Save("true", "de", "owner", start); err == nil || !strings.Contains(err.Error(), "de") {
		t.Fatalf("an unknown language: %v", err)
	}
	if err := f.Save("true", "", "owner", start); err != nil {
		t.Fatal(err)
	}
	if c, _ := f.Get(); c.Language != "" {
		t.Fatalf("empty is left to the default: %+v", c)
	}
}
