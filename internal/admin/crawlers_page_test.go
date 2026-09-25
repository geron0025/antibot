package admin

import (
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/crawlers"
	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
)

func newCrawlersServer(t *testing.T) (*Server, *crawlers.File) {
	t.Helper()
	s, dir := newServer(t)
	f, err := crawlers.Open(filepath.Join(dir, "shared", "crawlers.json"))
	if err != nil {
		t.Fatal(err)
	}
	s.o.Crawlers = f

	l, err := events.Open(events.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	l.Write(facts.Request{Time: now, IP: "66.249.66.1", Host: "a.ru", UA: "Googlebot/2.1",
		NetClass: "crawler", NetProtected: true, NetOwner: "Google", Decision: "allow", Rule: "verified crawler"})
	l.Write(facts.Request{Time: now, IP: "20.1.1.2", Host: "a.ru", UA: "GPTBot/1.0",
		NetClass: "crawler", NetOwner: "OpenAI", Decision: "block", Rule: "block-curl", Status: 403})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return s, f
}

// The tab shows who came, whether they pass, and a switch.
func TestCrawlersTabShowsWhoCame(t *testing.T) {
	s, _ := newCrawlersServer(t)
	cookies := logIn(t, s)
	resp := get(t, s, "/rules/crawlers", cookies)
	body, _ := io.ReadAll(resp.Body)
	page := string(body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, want := range []string{"Google", "OpenAI", `value="pass_off"`, `value="hold"`, "/rules/crawlers"} {
		if !strings.Contains(page, want) {
			t.Errorf("the tab lacks %q", want)
		}
	}
	// OpenAI here is a collector of training data: named, never offered
	// a pass.
	if strings.Count(page, `name="owner" value="OpenAI"`) != 0 {
		t.Error("a collector of training data is offered the pass")
	}
}

// Turning the pass off and holding an owner back ask for the password;
// letting through again does not.
func TestCrawlersSwitches(t *testing.T) {
	s, f := newCrawlersServer(t)
	cookies := logIn(t, s)
	post := func(form url.Values) int {
		form.Set("csrf", tokenFrom(cookies))
		return postForm(t, s, "/rules/crawlers", cookies, form).Code
	}

	post(url.Values{"do": {"pass_off"}, "password": {"wrong"}})
	if !f.Get().Pass {
		t.Fatal("the pass went off on a wrong password")
	}
	post(url.Values{"do": {"pass_off"}, "password": {password}})
	if f.Get().Pass {
		t.Fatal("the pass did not go off")
	}
	post(url.Values{"do": {"pass_on"}})
	if !f.Get().Pass {
		t.Fatal("the pass did not come back without a password")
	}

	post(url.Values{"do": {"hold"}, "owner": {"Google"}})
	if f.Get().Holds("Google") {
		t.Fatal("an owner was held back without a password")
	}
	post(url.Values{"do": {"hold"}, "owner": {"Google"}, "password": {password}})
	if st := f.Get(); !st.Holds("Google") || st.UpdatedBy != "owner" {
		t.Fatalf("settings %+v", st)
	}
	post(url.Values{"do": {"release"}, "owner": {"Google"}})
	if f.Get().Holds("Google") {
		t.Fatal("the owner was not let through again")
	}

	// A foreign form changes nothing.
	postForm(t, s, "/rules/crawlers", cookies, url.Values{"do": {"pass_off"}, "password": {password}})
	if !f.Get().Pass {
		t.Fatal("a form without the token turned the pass off")
	}
}
