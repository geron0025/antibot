// Package admin is the node's admin UI.
//
// It shows events, statistics, rules and domains, and can change a
// counted few things: enable or disable an already written rule, add or
// remove a domain, upload a ready-made certificate. Composing a rule
// condition, editing the settings or creating an account through it is
// impossible — that is done with commands, and there is no second path:
// the admin UI stands on somebody else's perimeter, and a hole in it must
// not become a hole in the site's protection.
//
// Every change goes through the same file write and the same validation
// as the commands — `antibot rules` and `antibot domains`: one engine,
// one write path, and the node's log says who changed what from where.
//
// It exists because an antibot whose work is invisible never gets put
// into blocking mode: a human first looks at whom the node is about to
// cut off, and only then allows it to do so.
package admin

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/domains"
	"github.com/geron0025/antibot/internal/edgetls"
	"github.com/geron0025/antibot/internal/rules"
)

// Options of the admin UI.
type Options struct {
	// Addr to listen on. Loopback by default: an admin UI on 0.0.0.0 is
	// an open door on somebody else's perimeter.
	Addr string

	// HTTPAddr, when set together with a certificate, answers with a
	// redirect to HTTPS with code 308.
	HTTPAddr string

	// Cert and Key are the certificate files. Without them the admin UI
	// agrees to work only on loopback.
	Cert, Key string

	Users    *Users
	Sessions *Sessions

	// Attempts bounds password guessing. The same limiter as the rules
	// use: there is no point in a second one.
	Attempts *rules.Windows

	EventsDir string
	Rules     *rules.Store

	// Domains is the file of domains added at run time; ConfigRoutes are
	// the routes led by hand in config.yaml, shown but never written.
	Domains      *domains.Store
	ConfigRoutes map[string]string

	// Certs shows what serves each name; UploadedCertsDir is where an
	// uploaded pair lands. With an empty directory uploads are off.
	Certs            *edgetls.Set
	UploadedCertsDir string

	Version string
	Log     *slog.Logger
}

// Server is the admin UI.
type Server struct {
	o         Options
	templates *template.Template

	// Replaceable in tests: the domains page must not depend on the DNS
	// and the interfaces of the machine the tests run on.
	lookupHost func(context.Context, string) ([]string, error)
	ownAddrs   func() []netip.Addr
}

// New validates the options and assembles the admin UI.
//
// Two checks here matter more than the rest of the code in the package:
// without accounts the admin UI does not come up at all, and a
// non-loopback address without a certificate is a refusal. A password
// travelling the network in clear text is not an "inconvenience" but
// access already granted.
func New(o Options) (*Server, error) {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Addr == "" {
		o.Addr = "127.0.0.1:8090"
	}
	if o.Users == nil || !o.Users.Any() {
		return nil, fmt.Errorf("the admin UI is enabled but there are no accounts: create one with `antibot admin passwd`")
	}
	if o.Sessions == nil {
		o.Sessions = NewSessions(12 * time.Hour)
	}

	withTLS := o.Cert != "" && o.Key != ""
	if !withTLS {
		external, err := notLoopback(o.Addr)
		if err != nil {
			return nil, err
		}
		if external {
			return nil, fmt.Errorf("the admin UI on %s without a certificate: the password would travel "+
				"the network in clear text; set certificate/key or listen on 127.0.0.1", o.Addr)
		}
	}
	if o.HTTPAddr != "" && !withTLS {
		return nil, fmt.Errorf("admin_ui.redirect_from is set and there is no certificate: nowhere to redirect to")
	}

	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{o: o, templates: templates}, nil
}

// notLoopback answers whether the address faces outwards. An unparsed
// address counts as external: doubt here is resolved towards refusal.
func notLoopback(addr string) (bool, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true, fmt.Errorf("admin UI address %q: %w", addr, err)
	}
	if host == "" {
		// An empty host means "all interfaces".
		return true, nil
	}
	if host == "localhost" {
		return false, nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return true, nil
	}
	return !ip.IsLoopback(), nil
}

// Serve brings the listeners up and works for as long as the context
// lives.
func (s *Server) Serve(ctx context.Context) error {
	srv := &http.Server{
		Addr:              s.o.Addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()

	withTLS := s.o.Cert != "" && s.o.Key != ""
	if s.o.HTTPAddr != "" {
		go s.redirectHTTP(ctx)
	}

	s.o.Log.Info("listening for the admin UI", "address", s.o.Addr, "tls", withTLS)

	var err error
	if withTLS {
		err = srv.ListenAndServeTLS(s.o.Cert, s.o.Key)
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("admin UI: %w", err)
	}
	return nil
}

// redirectHTTP answers plain HTTP with a redirect using code 308.
//
// 308 rather than 301: 301 allows the browser to change the method to
// GET, and a submitted login form would silently turn into an empty
// request.
func (s *Server) redirectHTTP(ctx context.Context) {
	srv := &http.Server{
		Addr:              s.o.HTTPAddr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := r.Host
			if h, _, err := net.SplitHostPort(host); err == nil {
				host = h
			}
			_, port, err := net.SplitHostPort(s.o.Addr)
			if err == nil && port != "443" {
				host = net.JoinHostPort(host, port)
			}
			http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
		}),
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		s.o.Log.Error("admin UI redirect", "err", err)
	}
}

func shutdown(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}

// Handler assembles the routes. Separate from Serve so that a test can
// exercise the admin UI without a listener.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /style.css", s.style)

	mux.Handle("GET /{$}", s.requireLogin(s.overviewPage))
	mux.Handle("GET /events", s.requireLogin(s.eventsPage))
	mux.Handle("GET /rules", s.requireLogin(s.rulesPage))
	mux.Handle("GET /domains", s.requireLogin(s.domainsPage))

	// The writing actions, all of them. Composing a rule here is
	// impossible — only enabling or disabling an already written one;
	// domains and certificates are the owner's own risk, taken by the
	// product decision of 10 September 2026. Every write goes through
	// the same validation and the same atomic replacement as the
	// commands, and lands in the node's log with a name and an address.
	mux.Handle("POST /rules/toggle", s.requireLogin(s.toggleRule))
	mux.Handle("POST /rules/mode", s.requireLogin(s.setRuleMode))
	mux.Handle("POST /domains/add", s.requireLogin(s.addDomain))
	mux.Handle("POST /domains/remove", s.requireLogin(s.removeDomain))
	mux.Handle("POST /domains/certificate", s.requireLogin(s.uploadCertificate))

	return s.securityHeaders(mux)
}

// securityHeaders closes what headers can close.
//
// A strict CSP is cheap here: the pages are assembled on the server,
// there is no JavaScript of our own at all, and forbidding everything
// external breaks nothing.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// The admin UI shows the events of somebody else's site: it has
		// no business in search results, even if it is one day exposed to
		// the outside.
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// requireLogin closes a page behind a login.
func (s *Server) requireLogin(next func(http.ResponseWriter, *http.Request, string)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil {
			s.toLogin(w, r)
			return
		}
		name, ok := s.o.Sessions.Whose(cookie.Value, time.Now())
		if !ok {
			s.toLogin(w, r)
			return
		}
		next(w, r, name)
	})
}

func (s *Server) toLogin(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// clientAddr is needed for counting login attempts. Headers are not
// trusted here: the admin UI stands on loopback or behind its own TLS,
// and a forged X-Forwarded-For would let the guessing limit be bypassed.
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func truncate(s string, limit int) string {
	runes := []rune(s)
	if len(runes) <= limit {
		return s
	}
	return string(runes[:limit]) + "…"
}

// share prints a fraction as a percentage for the template.
func share(part, whole int) string {
	if whole == 0 {
		return "0%"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(part)/float64(whole))
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02.01 15:04:05")
}

func lower(s string) string { return strings.ToLower(s) }
