package admin

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// fakeControl is the link, as far as the page is concerned.
type fakeControl struct {
	state      *CloudState
	registered int
	answered   [][2]bool
	forgotten  int
	err        error
}

func (f *fakeControl) Answer(facts, aggregates bool) error {
	if f.err != nil {
		return f.err
	}
	f.answered = append(f.answered, [2]bool{facts, aggregates})
	f.state.Answered = true
	f.state.Fetching, f.state.Sending = facts, aggregates
	return nil
}

func (f *fakeControl) Register(_ context.Context, facts, aggregates bool) error {
	if f.err != nil {
		return f.err
	}
	f.registered++
	f.state.Token = true
	f.state.Tenant = "node-01jb8z0k"
	return f.Answer(facts, aggregates)
}

func (f *fakeControl) Forget() error {
	f.forgotten++
	*f.state = CloudState{Answered: true}
	return nil
}

func withCloud(t *testing.T, state *CloudState, control CloudControl) *Server {
	t.Helper()
	s, _ := newServer(t)
	s.o.Cloud = func() CloudState { return *state }
	s.o.CloudControl = control
	return s
}

// postCloud fills in the token the forms carry, so that each test says
// only what it is about.
func postCloud(t *testing.T, s *Server, path string, cookies []*http.Cookie, form url.Values) *http.Response {
	t.Helper()
	form.Set("csrf", tokenFrom(cookies))
	return postForm(t, s, path, cookies, form).Result()
}

// The owner is asked once, at his first login, and on the page he lands
// on rather than one he has to find.
func TestTheFirstLoginAsksTheTwoQuestions(t *testing.T) {
	state := &CloudState{}
	s := withCloud(t, state, &fakeControl{state: state})
	cookies := logIn(t, s)

	resp := get(t, s, "/", cookies)
	if resp.StatusCode != http.StatusSeeOther ||
		resp.Header.Get("Location") != "/settings/cloud?welcome=1" {
		t.Fatalf("%d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	body, _ := io.ReadAll(get(t, s, "/settings/cloud?welcome=1", cookies).Body)
	page := string(body)
	for _, want := range []string{"Receive security updates", "Send statistics"} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not offer %q", want)
		}
	}
	// Both off until the owner says otherwise: a pre-ticked box is
	// exactly what other antibots are rightly blamed for.
	if strings.Contains(page, "checked") {
		t.Error("a box was ticked for him")
	}
}

// Saying no to both is an answer, and the node stops asking.
func TestNoToBothIsAnAnswerAndTheNodeStopsAsking(t *testing.T) {
	state := &CloudState{}
	control := &fakeControl{state: state}
	s := withCloud(t, state, control)
	cookies := logIn(t, s)

	resp := postCloud(t, s, "/settings/cloud/save", cookies, url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", resp.StatusCode)
	}
	if control.registered != 0 {
		t.Error("the node registered although it was told to do nothing")
	}
	if len(control.answered) != 1 || control.answered[0] != [2]bool{false, false} {
		t.Fatalf("what was recorded: %v", control.answered)
	}

	if resp := get(t, s, "/", cookies); resp.StatusCode == http.StatusSeeOther &&
		resp.Header.Get("Location") == "/settings/cloud?welcome=1" {
		t.Error("the owner is asked again after answering")
	}
}

// Ticking either box gets a token — the owner copies nothing and writes
// to nobody.
func TestTickingABoxTakesAToken(t *testing.T) {
	state := &CloudState{}
	control := &fakeControl{state: state}
	s := withCloud(t, state, control)
	cookies := logIn(t, s)

	resp := postCloud(t, s, "/settings/cloud/save", cookies, url.Values{"facts": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", resp.StatusCode)
	}
	if control.registered != 1 {
		t.Fatalf("registered %d times", control.registered)
	}
	if len(control.answered) != 1 || control.answered[0] != [2]bool{true, false} {
		t.Fatalf("what was recorded: %v", control.answered)
	}

	// With a token in hand the next change does not register again.
	postCloud(t, s, "/settings/cloud/save", cookies, url.Values{"facts": {"1"}, "aggregates": {"1"}})
	if control.registered != 1 {
		t.Errorf("registered again: %d", control.registered)
	}
}

// What the cloud refused with reaches the owner in his own words: the
// three failures need three different things from him.
func TestARefusalIsShownToTheOwner(t *testing.T) {
	state := &CloudState{}
	control := &fakeControl{state: state, err: CloudRefusal("this installation already took a token once")}
	s := withCloud(t, state, control)
	cookies := logIn(t, s)

	resp := postCloud(t, s, "/settings/cloud/save", cookies, url.Values{"facts": {"1"}})
	to := resp.Header.Get("Location")
	if !strings.Contains(to, "already+took+a+token") {
		t.Fatalf("the owner was sent to %q", to)
	}
}

// A token in the settings file outranks the page: the checkboxes are
// shown as what they are, and nothing here can override the file.
func TestASettingsFileTokenIsNotOverridden(t *testing.T) {
	state := &CloudState{Token: true, FromConfig: true, Answered: true,
		Fetching: true, Sending: true}
	s := withCloud(t, state, nil)
	cookies := logIn(t, s)

	body, _ := io.ReadAll(get(t, s, "/settings/cloud", cookies).Body)
	page := string(body)
	if !strings.Contains(page, "config.yaml") || !strings.Contains(page, "disabled") {
		t.Error("the page does not say the settings file decides")
	}

	resp := postCloud(t, s, "/settings/cloud/save", cookies, url.Values{"facts": {"1"}})
	if to := resp.Header.Get("Location"); !strings.Contains(to, "config.yaml") {
		t.Errorf("a save against a settings file token went to %q", to)
	}

	// And such a node is not sent to the welcome page: it was set up by
	// somebody who already decided.
	if resp := get(t, s, "/", cookies); resp.StatusCode == http.StatusSeeOther {
		t.Error("a node configured by hand was sent to the questions")
	}
}

// Forgetting is offered only where there is a token to forget.
func TestForgettingClearsEverything(t *testing.T) {
	state := &CloudState{Token: true, Answered: true, Fetching: true, Tenant: "node-1"}
	control := &fakeControl{state: state}
	s := withCloud(t, state, control)
	cookies := logIn(t, s)

	if resp := postCloud(t, s, "/settings/cloud/forget", cookies, url.Values{}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%d", resp.StatusCode)
	}
	if control.forgotten != 1 || state.Token {
		t.Fatalf("forgotten %d times, token %v", control.forgotten, state.Token)
	}
}

// The page works on a node whose admin UI was given no link at all: the
// block is left out rather than the page failing.
func TestThePageStandsWithoutALink(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	if resp := get(t, s, "/settings/cloud", cookies); resp.StatusCode != http.StatusOK {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// The cloud is a tab of the settings: the menu has no item of its own for
// it, and the old address still leads there.
func TestTheCloudIsATabOfTheSettings(t *testing.T) {
	s, _ := newServer(t)
	cookies := logIn(t, s)

	body, _ := io.ReadAll(get(t, s, "/settings/cloud", cookies).Body)
	page := string(body)
	for _, want := range []string{`href="/settings" class="current">Settings</a>`,
		`href="/settings/cloud" class="current"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page has no %q", want)
		}
	}
	start := strings.Index(page, "<nav>")
	if nav := page[start : start+strings.Index(page[start:], "</nav>")]; strings.Contains(nav, "/cloud") {
		t.Error("the menu still has an item for the cloud")
	}

	resp := get(t, s, "/cloud?welcome=1", cookies)
	if resp.StatusCode != http.StatusMovedPermanently ||
		resp.Header.Get("Location") != "/settings/cloud?welcome=1" {
		t.Fatalf("/cloud: %d to %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
