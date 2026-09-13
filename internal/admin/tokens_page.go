package admin

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"time"
)

// tokenRow is a token as the page shows it.
type tokenRow struct {
	Token
	Status   string
	DaysLeft int
	Used     time.Time
}

// issuedToken is the token just issued. Its value is on the page once and
// nowhere else, ever: the node keeps the hash.
type issuedToken struct {
	Name, Scope, Value string
}

type tokensData struct {
	pageCommon
	CSRF    string
	Rows    []tokenRow
	MaxDays int
	Issued  *issuedToken
}

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, user string) {
	s.renderTokens(w, r, user, r.URL.Query().Get("error"), nil)
}

func (s *Server) renderTokens(w http.ResponseWriter, r *http.Request, user, message string, issued *issuedToken) {
	list, err := s.o.Tokens.List()
	if err != nil && message == "" {
		message = err.Error()
	}
	now := time.Now()

	// Live first, then the newest: the page is opened to find a token that
	// works, or to revoke one.
	sort.SliceStable(list, func(i, j int) bool {
		li, lj := list[i].State(now) == TokenLive, list[j].State(now) == TokenLive
		if li != lj {
			return li
		}
		return list[i].CreatedAt.After(list[j].CreatedAt)
	})
	rows := make([]tokenRow, 0, len(list))
	for _, t := range list {
		row := tokenRow{Token: t, Status: t.State(now), DaysLeft: int(t.ExpiresAt.Sub(now).Hours() / 24)}
		if t.UsedAt != nil {
			row.Used = *t.UsedAt
		}
		rows = append(rows, row)
	}

	s.render(w, "tokens.html", tokensData{
		pageCommon: s.common(user, "tokens", 0, message),
		CSRF:       s.csrfToken(r),
		Rows:       rows,
		MaxDays:    MaxTokenDays,
		Issued:     issued,
	})
}

// issueToken asks for the password once more. A session is enough to
// look around and to switch a rule off, but a token outlives the session
// by months: whoever stole a cookie must not be able to turn it into a
// year of access — the same reason an account cannot be changed here.
func (s *Server) issueToken(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}

	// The same counter as the login form: guessing the password here must
	// not be a way around the limit there.
	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		http.Error(w, "Too many attempts. Please wait.", http.StatusTooManyRequests)
		return
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("an API token was not issued: the password did not match",
			"who", who, "address", clientAddr(r))
		s.tokensError(w, r, "The password did not match")
		return
	}

	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil {
		s.tokensError(w, r, "The number of days is not a number")
		return
	}
	value, tok, err := s.o.Tokens.Issue(r.PostFormValue("name"), r.PostFormValue("scope"), days, who, now)
	if err != nil {
		s.o.Log.Error("an API token was not issued", "who", who, "err", err)
		s.tokensError(w, r, err.Error())
		return
	}

	s.o.Log.Info("an API token was issued from the admin UI",
		"token", tok.Name, "scope", tok.Scope, "expires", tok.ExpiresAt.Format(time.DateOnly),
		"who", who, "address", clientAddr(r))
	// Rendered in the answer to the POST rather than after a redirect:
	// the value must not travel in an address, and the page is no-store.
	s.renderTokens(w, r, who, "", &issuedToken{Name: tok.Name, Scope: tok.Scope, Value: value})
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	name := r.PostFormValue("name")
	if err := s.o.Tokens.Revoke(name, time.Now()); err != nil {
		s.o.Log.Error("an API token was not revoked", "token", name, "who", who, "err", err)
		s.tokensError(w, r, err.Error())
		return
	}
	s.o.Log.Info("an API token was revoked from the admin UI",
		"token", name, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/tokens", http.StatusSeeOther)
}

func (s *Server) tokensError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/tokens?error="+url.QueryEscape(message), http.StatusSeeOther)
}
