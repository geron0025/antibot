package admin

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/geron0025/antibot/internal/domains"
	"github.com/geron0025/antibot/internal/edgetls"
)

// The uploaded pair is two PEM files; a megabyte holds any real chain
// with room to spare, and the admin UI must not be a way to fill the
// disk.
const maxUploadBytes = 1 << 20

// DomainRow is one served name on the domains page.
type DomainRow struct {
	Host string
	To   string

	// FromConfig marks a route led by hand in config.yaml. It is shown
	// but not editable here: the admin UI must not override what the
	// machine's owner wrote.
	FromConfig bool

	// Shadowed marks a domain that is in the file but silenced by a
	// configuration route with the same name.
	Shadowed bool

	// Certificate serving the name; nil means the self-signed fallback.
	Cert *CertState

	// DNS is the hint about where the name points. A hint, not a
	// condition: the node may stand behind NAT and not know its own
	// public address.
	DNS string
}

// CertState is what the owner needs to know about a certificate: that
// it is there, and when it stops being there.
type CertState struct {
	Names    string
	NotAfter time.Time
	Days     int
	Expiring bool
}

// expiryWarning is how long before the expiry the admin UI starts
// warning. There is no auto-renewal, so the warning is the renewal
// mechanism.
const expiryWarning = 14 * 24 * time.Hour

func (s *Server) certState(host string, now time.Time) *CertState {
	if s.o.Certs == nil {
		return nil
	}
	leaf := s.o.Certs.Covering(host)
	if leaf == nil {
		return nil
	}
	return certStateOf(leaf.DNSNames, leaf.Subject.CommonName, leaf.NotAfter, now)
}

func certStateOf(names []string, common string, until time.Time, now time.Time) *CertState {
	shown := strings.Join(names, ", ")
	if shown == "" {
		shown = common
	}
	days := int(until.Sub(now).Hours() / 24)
	return &CertState{
		Names:    shown,
		NotAfter: until,
		Days:     days,
		Expiring: until.Sub(now) < expiryWarning,
	}
}

type domainsData struct {
	pageCommon
	CSRF      string
	Rows      []DomainRow
	Fallback  string // the default route from the configuration, if any
	CanUpload bool
}

func (s *Server) domainsPage(w http.ResponseWriter, r *http.Request, user string) {
	now := time.Now()
	data := domainsData{
		pageCommon: s.common(user, "domains", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
		CanUpload:  s.o.UploadedCertsDir != "",
	}

	inConfig := map[string]bool{}
	for host, to := range s.o.ConfigRoutes {
		if host == "*" {
			data.Fallback = to
			continue
		}
		inConfig[host] = true
		data.Rows = append(data.Rows, DomainRow{
			Host: host, To: to, FromConfig: true, Cert: s.certState(host, now),
		})
	}
	sort.Slice(data.Rows, func(i, j int) bool { return data.Rows[i].Host < data.Rows[j].Host })

	if s.o.Domains != nil {
		for _, d := range s.o.Domains.List() {
			data.Rows = append(data.Rows, DomainRow{
				Host: d.Host, To: d.To, Shadowed: inConfig[d.Host],
				Cert: s.certState(d.Host, now),
			})
		}
	}

	s.fillDNS(r.Context(), data.Rows)
	s.render(w, "domains.html", data)
}

// fillDNS resolves every exact name and says whether it points at this
// machine. Concurrently and with a short deadline: the page must not
// hang on somebody's slow resolver.
func (s *Server) fillDNS(ctx context.Context, rows []DomainRow) {
	lookup := s.lookupHost
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
	own := s.ownAddrs
	if own == nil {
		own = localAddrs
	}
	mine := map[netip.Addr]bool{}
	for _, a := range own() {
		mine[a.Unmap()] = true
	}

	ctx, cancel := context.WithTimeout(ctx, 800*time.Millisecond)
	defer cancel()

	var group sync.WaitGroup
	for i := range rows {
		if strings.HasPrefix(rows[i].Host, "*.") {
			rows[i].DNS = "—"
			continue
		}
		group.Add(1)
		go func(row *DomainRow) {
			defer group.Done()
			row.DNS = dnsHint(ctx, lookup, mine, row.Host)
		}(&rows[i])
	}
	group.Wait()
}

func dnsHint(ctx context.Context, lookup func(context.Context, string) ([]string, error),
	mine map[netip.Addr]bool, host string) string {
	found, err := lookup(ctx, host)
	if err != nil || len(found) == 0 {
		return "no address in DNS"
	}
	for _, a := range found {
		if ip, err := netip.ParseAddr(a); err == nil && mine[ip.Unmap()] {
			return "points here"
		}
	}
	return "points at " + strings.Join(found, ", ")
}

// localAddrs lists the machine's own addresses — what "the domain
// points here" is checked against.
func localAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr())
		}
	}
	return out
}

// siteAddress turns the server field into the upstream address. The
// scheme may be left out — then it is http, the usual case for a site
// on the same machine or in the same network. A bare IPv6 address is
// bracketed, the way a URL needs it.
func siteAddress(server string) string {
	server = strings.TrimSpace(server)
	scheme := "http"
	if i := strings.Index(server, "://"); i >= 0 {
		scheme, server = server[:i], server[i+3:]
	}
	server = strings.TrimSuffix(server, "/")
	if strings.Count(server, ":") > 1 && !strings.HasPrefix(server, "[") {
		server = "[" + server + "]"
	}
	return scheme + "://" + server
}

// addDomain adds a served name: the name and the site's server.
func (s *Server) addDomain(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.o.Domains == nil {
		http.Error(w, "the domains are not connected", http.StatusNotFound)
		return
	}

	host := r.PostFormValue("host")
	server := r.PostFormValue("server")
	if strings.TrimSpace(server) == "" {
		s.domainsError(w, r, "no site server given")
		return
	}

	added, err := s.o.Domains.Add(host, siteAddress(server))
	if err != nil {
		s.o.Log.Error("the domain was not added", "host", host, "who", who, "err", err)
		s.domainsError(w, r, err.Error())
		return
	}

	// Who pointed what where goes into the node's log: a change of
	// where a site's traffic flows must not happen anonymously.
	s.o.Log.Info("a domain was added from the admin UI",
		"host", added.Host, "to", added.To, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

func (s *Server) removeDomain(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.o.Domains == nil {
		http.Error(w, "the domains are not connected", http.StatusNotFound)
		return
	}

	host := r.PostFormValue("host")
	if err := s.o.Domains.Remove(host); err != nil {
		s.o.Log.Error("the domain was not removed", "host", host, "who", who, "err", err)
		s.domainsError(w, r, err.Error())
		return
	}

	s.o.Log.Info("a domain was removed from the admin UI",
		"host", host, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

// uploadCertificate takes a ready-made pair — the chain and the key —
// and puts it where the certificate scanner looks. The node does not
// issue certificates: whoever wants automatic issuance runs certbot
// next to it, as before.
func (s *Server) uploadCertificate(w http.ResponseWriter, r *http.Request, who string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		s.domainsError(w, r, "the upload was not accepted: two PEM files under a megabyte")
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}
	if s.o.UploadedCertsDir == "" || s.o.Certs == nil {
		http.Error(w, "uploads are not connected", http.StatusNotFound)
		return
	}

	// The form lives in the domain's card: the domain arrives in a hidden
	// field and is never typed. It is checked all the same — a form is
	// only a form.
	host, err := domains.NormalizeHost(r.PostFormValue("host"))
	if err != nil {
		s.domainsError(w, r, err.Error())
		return
	}
	if !s.serves(host) {
		s.domainsError(w, r, fmt.Sprintf("the node does not serve %s", host))
		return
	}

	chain, err := formFile(r, "fullchain")
	if err != nil {
		s.domainsError(w, r, "the certificate chain: "+err.Error())
		return
	}
	key, err := formFile(r, "privkey")
	if err != nil {
		s.domainsError(w, r, "the private key: "+err.Error())
		return
	}

	until, err := s.installCertificate(host, chain, key)
	if err != nil {
		s.o.Log.Error("the certificate was not accepted", "host", host, "who", who, "err", err)
		s.domainsError(w, r, host+": "+err.Error())
		return
	}

	s.o.Log.Info("a certificate was uploaded from the admin UI",
		"host", host, "not_after", until.Format("2006-01-02"), "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/domains", http.StatusSeeOther)
}

// serves answers whether the name is on either list — the file or the
// configuration.
func (s *Server) serves(host string) bool {
	if _, ok := s.o.ConfigRoutes[host]; ok && host != "*" {
		return true
	}
	if s.o.Domains != nil {
		for _, d := range s.o.Domains.List() {
			if d.Host == host {
				return true
			}
		}
	}
	return false
}

func formFile(r *http.Request, field string) ([]byte, error) {
	file, _, err := r.FormFile(field)
	if err != nil {
		return nil, fmt.Errorf("no file")
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxUploadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) == 0 {
		return nil, fmt.Errorf("the file is empty")
	}
	if len(contents) > maxUploadBytes {
		return nil, fmt.Errorf("bigger than a megabyte")
	}
	return contents, nil
}

// installCertificate validates and writes the pair, then makes it serve
// at once: a human who has just uploaded a certificate checks the site
// in the next breath, not after the timer.
func (s *Server) installCertificate(host string, chain, key []byte) (time.Time, error) {
	until, err := edgetls.Install(s.o.UploadedCertsDir, host, chain, key)
	if err != nil {
		return time.Time{}, err
	}
	s.o.Certs.Reload()
	return until, nil
}

func (s *Server) domainsError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/domains?error="+url.QueryEscape(message), http.StatusSeeOther)
}
