package admin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// CloudControl is what the admin UI may change about the link to the
// cloud: the owner's two answers, and taking a token when he wants one.
//
// An interface rather than the thing itself, because the admin UI must
// not know how either is done. It asks; whoever wired the node decides
// what that means.
type CloudControl interface {
	// Answer records the two checkboxes and applies them at once.
	Answer(facts, aggregates bool) error

	// Register asks the cloud for a token for this installation and
	// keeps it, then records the checkboxes.
	Register(ctx context.Context, facts, aggregates bool) error

	// Forget drops the token and clears both answers.
	Forget() error
}

// cloudData is the cloud page: the two questions, and what has come of
// them so far.
type cloudData struct {
	pageCommon
	CSRF string

	// Welcome marks the first visit, the one the owner is sent to right
	// after his first login.
	Welcome bool

	// Done is what to say after a change went through.
	Done string

	State *CloudState
}

// cloudPage shows the two checkboxes and the state of both directions.
func (s *Server) cloudPage(w http.ResponseWriter, r *http.Request, user string) {
	data := cloudData{
		pageCommon: s.common(user, "settings", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
		Welcome:    r.URL.Query().Get("welcome") == "1",
		Done:       r.URL.Query().Get("done"),
	}
	data.Tab = "cloud"
	if s.o.Cloud != nil {
		state := s.o.Cloud()
		data.State = &state
	}
	s.render(w, "cloud.html", data)
}

// saveCloud takes the two answers.
//
// Registration happens here and not in the background, and the owner
// waits the second it takes: he has just been told the node will fetch
// the bases, and a page that says "saved" while the node silently has
// no token would be a lie at the worst possible moment.
func (s *Server) saveCloud(w http.ResponseWriter, r *http.Request, user string) {
	if s.o.CloudControl == nil {
		http.Redirect(w, r, "/settings/cloud?error="+
			url.QueryEscape("this node's link to the cloud is set in config.yaml"), http.StatusSeeOther)
		return
	}

	facts := r.FormValue("facts") != ""
	aggregates := r.FormValue("aggregates") != ""

	var state CloudState
	if s.o.Cloud != nil {
		state = s.o.Cloud()
	}

	// A token is needed for either direction, and the node has none
	// until it asks for one. Nobody is asked to copy anything: that is
	// the whole point of the free level.
	if (facts || aggregates) && !state.Token {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()

		if err := s.o.CloudControl.Register(ctx, facts, aggregates); err != nil {
			s.o.Log.Error("the node did not register with the cloud", "err", err)
			http.Redirect(w, r, "/settings/cloud?error="+url.QueryEscape(cloudFailure(err)), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("registered"), http.StatusSeeOther)
		return
	}

	if err := s.o.CloudControl.Answer(facts, aggregates); err != nil {
		http.Redirect(w, r, "/settings/cloud?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("saved"), http.StatusSeeOther)
}

// forgetCloud drops the token. For the owner who wants the node to stop
// talking to the cloud at all rather than merely stop sending.
func (s *Server) forgetCloud(w http.ResponseWriter, r *http.Request, user string) {
	if s.o.CloudControl == nil {
		http.Redirect(w, r, "/settings/cloud", http.StatusSeeOther)
		return
	}
	if err := s.o.CloudControl.Forget(); err != nil {
		http.Redirect(w, r, "/settings/cloud?error="+url.QueryEscape(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("forgotten"), http.StatusSeeOther)
}

// cloudFailure turns what went wrong into what the owner can do about
// it. The three cases differ in exactly that.
func cloudFailure(err error) string {
	var refused *cloudRefusal
	switch {
	case errors.As(err, &refused):
		return refused.text
	default:
		return err.Error()
	}
}

// cloudRefusal lets whoever wires the node pass a refusal with words
// already chosen for a human.
type cloudRefusal struct{ text string }

func (c *cloudRefusal) Error() string { return c.text }

// CloudRefusal wraps a message meant for the owner rather than the log.
func CloudRefusal(text string) error { return &cloudRefusal{text: text} }
