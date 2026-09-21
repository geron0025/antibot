package admin

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/geron0025/antibot/internal/control"
)

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
	data.State = s.coreCloud(r.Context())
	if data.State == nil && data.Error == "" {
		data.Error = "the core does not answer: the link to the cloud cannot be shown or changed"
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
	state := s.coreCloud(r.Context())
	if state == nil {
		s.cloudError(w, r, "the core does not answer: nothing was changed")
		return
	}
	if state.FromConfig {
		s.cloudError(w, r, "this node's link to the cloud is set in config.yaml")
		return
	}

	facts := r.FormValue("facts") != ""
	aggregates := r.FormValue("aggregates") != ""

	// A token is needed for either direction, and the node has none
	// until it asks for one. Nobody is asked to copy anything: that is
	// the whole point of the free level.
	if (facts || aggregates) && !state.Token {
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()

		if err := s.o.Core.CloudRegister(ctx, facts, aggregates); err != nil {
			s.o.Log.Error("the node did not register with the cloud", "err", err)
			s.cloudError(w, r, cloudFailure(err))
			return
		}
		http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("registered"), http.StatusSeeOther)
		return
	}

	ctx, cancel := s.coreContext(r.Context())
	defer cancel()
	if err := s.o.Core.CloudAnswer(ctx, facts, aggregates); err != nil {
		s.cloudError(w, r, cloudFailure(err))
		return
	}
	http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("saved"), http.StatusSeeOther)
}

// forgetCloud drops the token. For the owner who wants the node to stop
// talking to the cloud at all rather than merely stop sending.
func (s *Server) forgetCloud(w http.ResponseWriter, r *http.Request, user string) {
	ctx, cancel := s.coreContext(r.Context())
	defer cancel()
	if err := s.o.Core.CloudForget(ctx); err != nil {
		s.cloudError(w, r, cloudFailure(err))
		return
	}
	http.Redirect(w, r, "/settings/cloud?done="+url.QueryEscape("forgotten"), http.StatusSeeOther)
}

func (s *Server) cloudError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/settings/cloud?error="+url.QueryEscape(message), http.StatusSeeOther)
}

// cloudFailure turns what went wrong into what the owner can do about
// it. A refusal carries words chosen for a human; a core that does not
// answer is said to be so; anything else is shown as it is.
func cloudFailure(err error) string {
	var refused *control.Refusal
	switch {
	case errors.As(err, &refused):
		return refused.Text
	case errors.Is(err, control.ErrUnreachable):
		return "the core does not answer: nothing was changed"
	default:
		return err.Error()
	}
}
