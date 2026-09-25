package admin

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/geron0025/antibot/internal/i18n"
)

// The admin UI speaks English and Russian. Every word a human reads comes
// from the catalogs in locales/: the templates through t and tn, the
// messages assembled in Go through the request's printer. What the code
// itself says — an error of the rules engine, a certificate, the core —
// stays as the code wrote it, the way it lands in the log.

//go:embed locales/*.json
var localesFS embed.FS

const langCookieName = "antibot_lang"

func loadCatalog() (*i18n.Catalog, error) {
	sub, err := fs.Sub(localesFS, "locales")
	if err != nil {
		return nil, err
	}
	return i18n.Load(sub, i18n.EN)
}

// lang is the language of a request: the viewer's own choice, then their
// browser's, then the one admin.yaml names.
func (s *Server) lang(r *http.Request) i18n.Lang {
	if c, err := r.Cookie(langCookieName); err == nil {
		if l, ok := i18n.Parse(c.Value); ok {
			return l
		}
	}
	fallback := s.o.Language
	if fallback == "" {
		fallback = i18n.EN
	}
	return i18n.Match(r.Header.Get("Accept-Language"), fallback)
}

func (s *Server) printer(r *http.Request) *i18n.Printer {
	return s.catalog.Printer(s.lang(r))
}

// t is a message in the request's language, for what is assembled in Go.
func (s *Server) t(r *http.Request, key string, args ...any) string {
	return s.printer(r).T(key, args...)
}

// localize is the templates' t. A key ending in _html is markup and goes
// into the page as it is, its arguments escaped; any other key is text,
// escaped by the template like any other value.
func localize(p *i18n.Printer, key string, args ...any) any {
	if !strings.HasSuffix(key, "_html") {
		return p.T(key, args...)
	}
	return template.HTML(p.T(key, escapeArgs(args)...))
}

// localizeN is the templates' tn: a message that depends on a count.
func localizeN(p *i18n.Printer, key string, n int, args ...any) any {
	if !strings.HasSuffix(key, "_html") {
		return p.N(key, n, args...)
	}
	return template.HTML(p.N(key, n, escapeArgs(args)...))
}

// escapeArgs makes the arguments of a markup message safe. Markup made by
// another t passes as it is; numbers are printed by the printer, which
// knows their format; everything else is text.
func escapeArgs(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case template.HTML:
			out[i] = string(v)
		case int, int64:
			out[i] = v
		default:
			out[i] = template.HTMLEscapeString(fmt.Sprint(v))
		}
	}
	return out
}

// setLanguage remembers the viewer's choice of language, for a year and
// in this browser only: it is a preference, not a setting of the node.
// It stands outside the login, so that the login page can switch too.
func (s *Server) setLanguage(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	lang, ok := i18n.Parse(r.PostFormValue("lang"))
	if !ok {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     langCookieName,
		Value:    string(lang),
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		// Lax rather than Strict: a link to the admin UI from a chat
		// should open in the language chosen, and the cookie carries no
		// power.
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, localPath(r.PostFormValue("back")), http.StatusSeeOther)
}

// localPath lets back through only as a path of this site: the form is
// only a form, and a switch of language must not become a redirect to
// somewhere else.
func localPath(back string) string {
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") || strings.HasPrefix(back, "/\\") {
		return "/"
	}
	u, err := url.Parse(back)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return back
}

// backOf is where the language switch of a page returns: the page itself.
// A page rendered in the answer to a form returns to the page the form
// lives on — the last step of the form's path is the action — and an
// error shown once is not shown again.
func backOf(r *http.Request) string {
	path := r.URL.Path
	if r.Method != http.MethodGet {
		if i := strings.LastIndex(path, "/"); i > 0 {
			path = path[:i]
		}
		return path
	}
	q := r.URL.Query()
	q.Del("error")
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}
