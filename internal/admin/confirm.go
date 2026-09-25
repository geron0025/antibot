package admin

import (
	"net/http"
	"time"
)

// The admin UI has one script of its own: the dialog that asks for the
// password again before an action that asks for it. The dialog itself is
// in the templates, in the page's language; the script only wires it to
// the forms marked data-confirm. Without the script — switched off, not
// loaded, a browser with no <dialog> — each form shows its own password
// field and works as it always did.

// confirmScript serves the script. From the admin UI itself: the CSP lets
// in scripts from here and nowhere else, and none inline.
func (s *Server) confirmScript(w http.ResponseWriter, r *http.Request) {
	contents, err := templatesFS.ReadFile("templates/confirm.js")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(contents)
}

// recheck asks for the password once more, for an action a stolen
// session must not be enough for. The attempts count against the same
// limit as the login form: guessing here must not be a way around it.
// On a refusal it answers the request itself — too many attempts, or
// fail with the words for a wrong password — and returns false.
func (s *Server) recheck(w http.ResponseWriter, r *http.Request, who, action string, fail func(message string)) bool {
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, time.Now()) {
		http.Error(w, s.t(r, "error.too_many_attempts"), http.StatusTooManyRequests)
		return false
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("an action was refused: the password did not match",
			"action", action, "who", who, "address", clientAddr(r))
		fail(s.t(r, "error.password"))
		return false
	}
	return true
}
