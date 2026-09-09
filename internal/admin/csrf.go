package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
)

// The "this request came from our own page" check, by double submission:
// a random value lies in a cookie and in a hidden form field, and they
// can only match if we were the ones who served the form.
//
// SameSite=Strict on the session cookie closes the same hole, but the
// session cookie lives for twelve hours, and browsers treat SameSite
// unevenly in older versions; the second check costs ten lines.

func (s *Server) setCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	if token := s.csrfToken(r); token != "" {
		return token, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	return token, nil
}

func (s *Server) csrfToken(r *http.Request) string {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (s *Server) checkCSRF(r *http.Request) bool {
	fromCookie := s.csrfToken(r)
	fromForm := r.PostFormValue("csrf")
	if fromCookie == "" || fromForm == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(fromCookie), []byte(fromForm)) == 1
}
