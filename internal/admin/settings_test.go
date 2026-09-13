package admin

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newSettingsServer is the test server with the admin UI's own pair in
// force, the way New leaves it when config.yaml names one.
func newSettingsServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, dir := newServer(t)
	chain, key := pemPair(t, time.Now().Add(90*24*time.Hour), "old.example.ru")
	s.o.Cert, s.o.Key = filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	if err := os.WriteFile(s.o.Cert, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.o.Key, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cert, err := loadCertificate(s.o.Cert, s.o.Key, s.o.Log)
	if err != nil {
		t.Fatal(err)
	}
	s.cert = cert
	s.o.CertDir = filepath.Join(dir, "admin-ui")
	return s, dir
}

func uploadAdmin(t *testing.T, s *Server, cookies []*http.Cookie, password string, chain, key []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("csrf", tokenFrom(cookies))
	w.WriteField("password", password)
	part, _ := w.CreateFormFile("fullchain", "fullchain.pem")
	part.Write(chain)
	part, _ = w.CreateFormFile("privkey", "privkey.pem")
	part.Write(key)
	w.Close()

	req := httptest.NewRequest("POST", "/settings/certificate", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp
}

func settingsErrorOf(resp *httptest.ResponseRecorder) string {
	location := resp.Header().Get("Location")
	if !strings.HasPrefix(location, "/settings?error=") {
		return ""
	}
	message, _ := url.QueryUnescape(strings.TrimPrefix(location, "/settings?error="))
	return message
}

func servedNames(s *Server) string { return strings.Join(s.cert.leaf().DNSNames, ",") }

func TestTheSettingsPageShowsTheAdminCertificate(t *testing.T) {
	s, _ := newSettingsServer(t)
	cookies := logIn(t, s)

	page := body(t, s, "/settings", cookies)
	for _, want := range []string{
		`<a href="/settings" class="current">Settings</a>`,
		"old.example.ru", "a self-signed certificate", "named in config.yaml",
		`action="/settings/certificate"`,
		// The test request comes for example.com, which the pair does not cover.
		"It does not cover",
		// A term runs into other years: the date carries the year.
		time.Now().Add(90 * 24 * time.Hour).Local().Format("02.01.2006"),
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the settings page has no %q", want)
		}
	}
}

// A new pair lands on the place config.yaml names and serves at once,
// not after the reread interval.
func TestReplacingTheAdminCertificate(t *testing.T) {
	s, _ := newSettingsServer(t)
	cookies := logIn(t, s)

	chain, key := pemPair(t, time.Now().Add(60*24*time.Hour), "admin.example.ru")
	resp := uploadAdmin(t, s, cookies, password, chain, key)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/settings" {
		t.Fatalf("the upload returned %d %s: %s", resp.Code, resp.Header().Get("Location"), settingsErrorOf(resp))
	}
	if got := servedNames(s); got != "admin.example.ru" {
		t.Errorf("the admin UI serves %s", got)
	}
	if on, _ := os.ReadFile(s.o.Cert); !bytes.Equal(on, chain) {
		t.Error("the certificate file holds the old chain")
	}
	if info, err := os.Stat(s.o.Key); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("the key: %v %v", info.Mode().Perm(), err)
	}
	if page := body(t, s, "/settings", cookies); !strings.Contains(page, "admin.example.ru") {
		t.Error("the page shows the old pair")
	}
}

// Every refusal leaves the previous pair serving.
func TestAdminCertificateRefusals(t *testing.T) {
	s, _ := newSettingsServer(t)
	cookies := logIn(t, s)

	good, goodKey := pemPair(t, time.Now().Add(30*24*time.Hour), "admin.example.ru")
	_, otherKey := pemPair(t, time.Now().Add(30*24*time.Hour), "admin.example.ru")
	expired, expiredKey := pemPair(t, time.Now().Add(-time.Minute), "admin.example.ru")

	for _, c := range []struct {
		name, password string
		chain, key     []byte
		want           string
	}{
		{"a wrong password", "not the password at all", good, goodKey, "did not match"},
		{"the key of another pair", password, good, otherKey, "was not accepted"},
		{"an expired certificate", password, expired, expiredKey, "expired"},
	} {
		resp := uploadAdmin(t, s, cookies, c.password, c.chain, c.key)
		if got := settingsErrorOf(resp); !strings.Contains(got, c.want) {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
		if got := servedNames(s); got != "old.example.ru" {
			t.Errorf("%s: the admin UI serves %s", c.name, got)
		}
	}
}

// certbot keeps links into its archive; replacing one with a file would
// cut its renewal off, so the page does not offer it and the upload is
// refused.
func TestCertbotLinksAreNotReplaced(t *testing.T) {
	s, dir := newSettingsServer(t)
	archive := filepath.Join(dir, "cert1.pem")
	if err := os.Rename(s.o.Cert, archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(archive, s.o.Cert); err != nil {
		t.Fatal(err)
	}
	cookies := logIn(t, s)

	page := body(t, s, "/settings", cookies)
	if !strings.Contains(page, "The files are links") || strings.Contains(page, `action="/settings/certificate"`) {
		t.Error("the page offers to replace certbot's links")
	}

	chain, key := pemPair(t, time.Now().Add(30*24*time.Hour), "admin.example.ru")
	resp := uploadAdmin(t, s, cookies, password, chain, key)
	if got := settingsErrorOf(resp); !strings.Contains(got, "is a link") {
		t.Errorf("the refusal: %q", got)
	}
	if info, err := os.Lstat(s.o.Cert); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced with a file")
	}
}

// Without a pair the listener is plain HTTP and cannot switch on the fly:
// the pair lands in the upload directory and serves from the next start.
func TestAPairAddedForTheNextStart(t *testing.T) {
	s, dir := newServer(t)
	s.o.CertDir = filepath.Join(dir, "admin-ui")
	cookies := logIn(t, s)

	if page := body(t, s, "/settings", cookies); !strings.Contains(page, "over plain HTTP") {
		t.Error("the page does not say the admin UI has no certificate")
	}

	chain, key := pemPair(t, time.Now().Add(60*24*time.Hour), "admin.example.ru")
	resp := uploadAdmin(t, s, cookies, password, chain, key)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/settings" {
		t.Fatalf("the upload returned %d %s: %s", resp.Code, resp.Header().Get("Location"), settingsErrorOf(resp))
	}
	page := body(t, s, "/settings", cookies)
	if !strings.Contains(page, "waits for the next start") || !strings.Contains(page, "admin.example.ru") {
		t.Error("the page does not show the pair waiting for the next start")
	}
	if s.cert != nil {
		t.Error("the plain listener got a certificate on the fly")
	}

	// The next start takes it up.
	certFile, keyFile := UploadedPair(s.o.CertDir)
	if certFile == "" {
		t.Fatal("no pair for the next start")
	}
	if _, err := loadCertificate(certFile, keyFile, s.o.Log); err != nil {
		t.Fatal(err)
	}
}
