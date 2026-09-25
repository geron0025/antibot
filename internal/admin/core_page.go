package admin

import (
	"net/http"
	"net/url"
	"time"

	"github.com/geron0025/antibot/internal/control"
)

// coreData is the settings tab about the core itself: whether it is up,
// since when, in which version.
type coreData struct {
	pageCommon
	CSRF string

	Health *control.Health
	Uptime time.Duration

	// Asked says a restart was asked a moment ago: the page is the one
	// the owner lands on, and it says what to expect rather than a core
	// that looks down.
	Asked bool
}

func (s *Server) corePage(w http.ResponseWriter, r *http.Request, user string) {
	data := coreData{
		pageCommon: s.common(r, user, "settings", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
		Asked:      r.URL.Query().Get("done") == "restart",
	}
	data.Tab = "core"
	ctx, cancel := s.coreContext(r.Context())
	defer cancel()
	if h, err := s.o.Core.Health(ctx); err == nil {
		data.Health = &h
		data.Uptime = time.Since(h.Started).Truncate(time.Second)
	}
	s.render(w, r, "core.html", data)
}

// restartCore asks the core to finish cleanly; the supervisor — systemd
// or docker — starts it again. The admin UI has no rights over the
// core's process and must not have: this is a request, and the core
// decides.
//
// The password is asked once more, as for a token: a restart breaks the
// connections of every site behind the node, and a stolen session must
// not be enough to do that at will.
func (s *Server) restartCore(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		http.Error(w, s.t(r, "error.too_many_attempts"), http.StatusTooManyRequests)
		return
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("the core was not restarted: the password did not match",
			"who", who, "address", clientAddr(r))
		s.coreError(w, r, s.t(r, "error.password"))
		return
	}

	ctx, cancel := s.coreContext(r.Context())
	defer cancel()
	if err := s.o.Core.Stop(ctx); err != nil {
		s.coreError(w, r, s.t(r, "core.not_restarted", err.Error()))
		return
	}
	s.o.Log.Warn("the core was asked to restart from the admin UI", "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/settings/core?done=restart", http.StatusSeeOther)
}

func (s *Server) coreError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/settings/core?error="+url.QueryEscape(message), http.StatusSeeOther)
}
