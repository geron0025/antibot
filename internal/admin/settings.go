package admin

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/edgetls"
)

// settingsData is the settings page: for now, the admin UI's own
// certificate. The page edits nothing in config.yaml — it takes a ready
// pair, the way the domains page does for the sites.
type settingsData struct {
	pageCommon
	CSRF string

	// Mode is what an upload does: "replace" — the pair in force, on the
	// fly; "add" — there is none, and the one uploaded serves from the
	// next start; "" — nothing can be uploaded.
	Mode string

	// CertFile and KeyFile are where the pair lies or will lie.
	// FromConfig says config.yaml names them; Linked, that they are
	// certbot's links, which are renewed with certbot and not here.
	CertFile, KeyFile string
	FromConfig        bool
	Linked            bool

	// Cert is the pair in force; Pending, one added and waiting for the
	// next start.
	Cert    *adminCert
	Pending *adminCert

	// Host is the name the page was opened with; Covers says whether the
	// pair in force fits it — the browser checks the same.
	Host   string
	Covers bool
}

type adminCert struct {
	Names      []string
	Issuer     string
	SelfSigned bool
	NotAfter   time.Time
	DaysLeft   int
}

// UploadedPair names the pair added on the settings page, when there is
// one: serve takes it when config.yaml names none.
func UploadedPair(dir string) (cert, key string) {
	if dir == "" {
		return "", ""
	}
	cert, key = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if _, err := os.Stat(cert); err != nil {
		return "", ""
	}
	if _, err := os.Stat(key); err != nil {
		return "", ""
	}
	return cert, key
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, user string) {
	data := settingsData{
		pageCommon: s.common(user, "settings", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
		Host:       requestHost(r),
	}
	data.Tab = "certificate"
	now := time.Now()
	switch {
	case s.cert != nil:
		data.Mode, data.CertFile, data.KeyFile = "replace", s.o.Cert, s.o.Key
		data.FromConfig = s.o.CertDir == "" || filepath.Dir(s.o.Cert) != filepath.Clean(s.o.CertDir)
		data.Linked = isLink(s.o.Cert) || isLink(s.o.Key)
		if leaf := s.cert.leaf(); leaf != nil {
			data.Cert = describeCert(leaf, now)
			data.Covers = data.Host == "" || leaf.VerifyHostname(data.Host) == nil
		}
	case s.o.CertDir != "":
		data.Mode = "add"
		data.CertFile, data.KeyFile = UploadedPair(s.o.CertDir)
		if data.CertFile != "" {
			if leaf, err := readLeaf(data.CertFile); err == nil {
				data.Pending = describeCert(leaf, now)
			}
		} else {
			data.CertFile = filepath.Join(s.o.CertDir, "fullchain.pem")
			data.KeyFile = filepath.Join(s.o.CertDir, "privkey.pem")
		}
	}
	s.render(w, "settings.html", data)
}

// uploadAdminCertificate replaces the admin UI's own pair on the fly, or
// adds one for the next start when there is none.
func (s *Server) uploadAdminCertificate(w http.ResponseWriter, r *http.Request, who string) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		s.settingsError(w, r, "the upload was not accepted: two PEM files under a megabyte")
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, "the request did not come from this page", http.StatusForbidden)
		return
	}

	var certFile, keyFile string
	switch {
	case s.cert != nil:
		certFile, keyFile = s.o.Cert, s.o.Key
	case s.o.CertDir != "":
		certFile, keyFile = filepath.Join(s.o.CertDir, "fullchain.pem"), filepath.Join(s.o.CertDir, "privkey.pem")
	default:
		s.settingsError(w, r, "there is nowhere to put the pair: admin_ui.uploaded_dir is empty")
		return
	}

	now := time.Now()
	if s.o.Attempts != nil &&
		s.o.Attempts.Exceeded("login:"+clientAddr(r), 10, 5*time.Minute, now) {
		http.Error(w, "Too many attempts. Please wait.", http.StatusTooManyRequests)
		return
	}
	if !s.o.Users.Check(who, r.PostFormValue("password")) {
		s.o.Log.Warn("the admin UI certificate was not replaced: the password did not match",
			"who", who, "address", clientAddr(r))
		s.settingsError(w, r, "The password did not match")
		return
	}

	chain, err := formFile(r, "fullchain")
	if err != nil {
		s.settingsError(w, r, "the certificate chain: "+err.Error())
		return
	}
	key, err := formFile(r, "privkey")
	if err != nil {
		s.settingsError(w, r, "the private key: "+err.Error())
		return
	}

	leaf, err := edgetls.InstallPair(certFile, keyFile, chain, key)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			err = fmt.Errorf("the node may not write next to %s: replace the files on the machine, "+
				"and the admin UI takes them up within 30 seconds", certFile)
		}
		s.o.Log.Error("the admin UI certificate was not accepted", "who", who, "err", err)
		s.settingsError(w, r, err.Error())
		return
	}

	names := strings.Join(describeCert(leaf, now).Names, ", ")
	if s.cert == nil {
		s.o.Log.Warn("an admin UI certificate was added from the admin UI, it serves from the next start",
			"names", names, "not_after", leaf.NotAfter.Format(time.DateOnly), "who", who, "address", clientAddr(r))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := s.cert.reload(); err != nil {
		// The pair was checked before it was written, so this is somebody
		// else writing the same files at the same moment.
		s.settingsError(w, r, "the pair was written and did not load: "+err.Error())
		return
	}
	s.o.Log.Warn("the admin UI certificate was replaced from the admin UI",
		"names", names, "not_after", leaf.NotAfter.Format(time.DateOnly), "who", who, "address", clientAddr(r))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) settingsError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/settings?error="+url.QueryEscape(message), http.StatusSeeOther)
}

func describeCert(leaf *x509.Certificate, now time.Time) *adminCert {
	names := edgetls.LeafNames(leaf)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" {
		issuer = leaf.Issuer.String()
	}
	return &adminCert{
		Names:      names,
		Issuer:     issuer,
		SelfSigned: bytes.Equal(leaf.RawIssuer, leaf.RawSubject),
		NotAfter:   leaf.NotAfter,
		DaysLeft:   int(leaf.NotAfter.Sub(now).Hours() / 24),
	}
}

func readLeaf(path string) (*x509.Certificate, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(contents)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	return x509.ParseCertificate(block.Bytes)
}

func isLink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

// requestHost is the name from the request, without the port.
func requestHost(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		return host
	}
	return r.Host
}
