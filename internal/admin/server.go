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
//
// On the same address, under /api/v1/, lives the node's API — the same
// numbers for a program, behind a token issued on the tokens page or with
// `antibot api-token`. The API takes a ready rule, the way `antibot rules
// add` does: one more door to the same write path, not an editor.
package admin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/alerts"
	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/domains"
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

	// CertDir is where a pair added on the settings page lands when Cert
	// and Key are empty; it serves from the next start. With Cert and Key
	// set, the settings page replaces those very files. An empty CertDir
	// turns adding off.
	CertDir string

	Users    *Users
	Sessions *Sessions

	// Attempts bounds password guessing. The admin UI's own: the rules'
	// limiter lives in the core's memory, and the admin UI has no access
	// to it.
	Attempts *rules.Windows

	EventsDir string
	Rules     *rules.Store

	// Domains is the file of domains added at run time. The routes
	// written by hand in the core's settings file come from Core, shown
	// but never written.
	Domains *domains.Store

	// UploadedCertsDir is where an uploaded site pair lands; the core
	// serves it as soon as it is asked to reread. With an empty directory
	// uploads are off.
	UploadedCertsDir string

	// Tokens are the API's. Nil turns the API and the tokens page off.
	Tokens *Tokens

	// AlertCommand is the file the delivery tab writes the command to.
	// Whether the alerts are on at all, and the command from the core's
	// settings file, which wins and is never changed here, come from Core.
	AlertCommand *alerts.CommandFile

	// Core is the node's core: what exists only in its memory, asked over
	// its control socket. The admin UI works while the core is down, and
	// says so on every page.
	Core control.Core

	Version string
	Log     *slog.Logger
}

// Server is the admin UI.
type Server struct {
	o         Options
	templates *template.Template
	cert      *certificate

	// Replaceable in tests: the domains page must not depend on the DNS
	// and the interfaces of the machine the tests run on.
	lookupHost func(context.Context, string) ([]string, error)
	ownAddrs   func() []netip.Addr

	// The ports, taken by Listen before anything is served.
	listener, redirectListener net.Listener
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
	if o.Core == nil {
		return nil, fmt.Errorf("the admin UI has no core to ask")
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

	var cert *certificate
	if withTLS {
		var err error
		if cert, err = loadCertificate(o.Cert, o.Key, o.Log); err != nil {
			return nil, err
		}
	}

	templates, err := parseTemplates()
	if err != nil {
		return nil, err
	}
	return &Server{o: o, templates: templates, cert: cert}, nil
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
// Listen takes the admin UI's ports, and the redirect's when there is
// one. Separate from Serve so that the node takes every port it has
// before it serves on any: a port somebody else holds is a refusal to
// start, said at once, rather than an admin UI that silently is not
// there while the proxy runs.
func (s *Server) Listen() error {
	if s.listener != nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.o.Addr)
	if err != nil {
		return fmt.Errorf("admin_ui.listen %s: %w", s.o.Addr, err)
	}
	if s.o.HTTPAddr != "" {
		redirect, err := net.Listen("tcp", s.o.HTTPAddr)
		if err != nil {
			ln.Close()
			return fmt.Errorf("admin_ui.redirect_from %s: %w", s.o.HTTPAddr, err)
		}
		s.redirectListener = redirect
	}
	s.listener = ln
	return nil
}

// Close gives the ports back when the node stops before serving.
func (s *Server) Close() {
	if s.listener != nil {
		s.listener.Close()
	}
	if s.redirectListener != nil {
		s.redirectListener.Close()
	}
}

func (s *Server) Serve(ctx context.Context) error {
	if err := s.Listen(); err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown(srv)
	}()

	withTLS := s.o.Cert != "" && s.o.Key != ""
	if s.redirectListener != nil {
		go s.redirectHTTP(ctx, s.redirectListener)
	}

	s.o.Log.Info("listening for the admin UI", "address", s.o.Addr, "tls", withTLS)

	var err error
	if withTLS {
		// The pair comes from the reloader rather than from the files
		// named here: a renewed certificate is taken up on the fly.
		srv.TLSConfig = &tls.Config{GetCertificate: s.cert.get, MinVersion: tls.VersionTLS12}
		err = srv.ServeTLS(s.listener, "", "")
	} else {
		err = srv.Serve(s.listener)
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
func (s *Server) redirectHTTP(ctx context.Context, ln net.Listener) {
	srv := &http.Server{
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
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
	mux.Handle("GET /events/export", s.requireLogin(s.exportEvents))
	mux.Handle("GET /rules", s.requireLogin(s.rulesPage))
	mux.Handle("GET /rule", s.requireLogin(s.rulePage))
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

	// The link to the cloud is a tab of the settings. /cloud is where it
	// lived before, and bookmarks of it still arrive.
	mux.Handle("GET /settings/cloud", s.requireLogin(s.cloudPage))
	mux.Handle("POST /settings/cloud/save", s.requireLogin(s.saveCloud))
	mux.Handle("POST /settings/cloud/forget", s.requireLogin(s.forgetCloud))
	mux.HandleFunc("GET /cloud", func(w http.ResponseWriter, r *http.Request) {
		target := "/settings/cloud"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})

	// The admin UI's own certificate. Replacing it asks for the password
	// once more: whoever holds its key reads the admin UI's traffic, and a
	// stolen session must not be enough to put the thief's key there.
	mux.Handle("GET /settings", s.requireLogin(s.settingsPage))
	mux.Handle("POST /settings/certificate", s.requireLogin(s.uploadAdminCertificate))

	// The alert command runs on the node's machine, so changing it asks
	// for the password once more, like issuing a token. Where alerts go is
	// a setting; what fires and what was sent is on the alerts page.
	// Whether the core has alerts at all is asked on each page: the core
	// may be restarted with other settings while the admin UI runs.
	mux.Handle("GET /alerts", s.requireLogin(s.alertsPage))
	mux.Handle("GET /settings/alerts", s.requireLogin(s.deliveryPage))
	mux.Handle("POST /settings/alerts/command", s.requireLogin(s.setAlertCommand))
	mux.Handle("POST /settings/alerts/test", s.requireLogin(s.testAlert))

	// API tokens are issued and revoked here, and the password is asked
	// once more for an issue: a token outlives a session by months.
	if s.o.Tokens != nil {
		mux.Handle("GET /tokens", s.requireLogin(s.tokensPage))
		mux.Handle("POST /tokens/issue", s.requireLogin(s.issueToken))
		mux.Handle("POST /tokens/revoke", s.requireLogin(s.revokeToken))
		s.apiRoutes(mux)
	}

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

// formatDate is for terms — a certificate's, a token's: they run into
// other years, and "15.12" alone does not say which.
func formatDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.Local().Format("02.01.2006")
}

func lower(s string) string { return strings.ToLower(s) }
