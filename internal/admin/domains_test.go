package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/domains"
	"github.com/geron0025/antibot/internal/edgetls"
)

// newDomainsServer is the ordinary test server with domains and
// certificates connected, and with DNS that does not leave the test.
func newDomainsServer(t *testing.T) (*Server, string) {
	t.Helper()
	s, dir := newServer(t)

	store, err := domains.Open(filepath.Join(dir, "domains.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	uploads := filepath.Join(dir, "certificates")
	s.o.Domains = store
	s.o.Certs = edgetls.Open([]string{uploads}, nil, nil)
	s.o.UploadedCertsDir = uploads
	s.o.ConfigRoutes = map[string]string{"hand.example.ru": "http://10.0.0.1", "*": "http://backend"}

	s.lookupHost = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "here.example.ru":
			return []string{"192.0.2.10"}, nil
		case "away.example.ru":
			return []string{"198.51.100.20"}, nil
		}
		return nil, &net404{}
	}
	s.ownAddrs = func() []netip.Addr { return []netip.Addr{netip.MustParseAddr("192.0.2.10")} }
	return s, dir
}

type net404 struct{}

func (*net404) Error() string { return "no such host" }

func postForm(t *testing.T, s *Server, path string, cookies []*http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp
}

func upload(t *testing.T, s *Server, cookies []*http.Cookie, csrf string, chain, key []byte) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	w.WriteField("csrf", csrf)
	part, _ := w.CreateFormFile("fullchain", "fullchain.pem")
	part.Write(chain)
	part, _ = w.CreateFormFile("privkey", "privkey.pem")
	part.Write(key)
	w.Close()

	req := httptest.NewRequest("POST", "/domains/certificate", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp := httptest.NewRecorder()
	s.Handler().ServeHTTP(resp, req)
	return resp
}

func pemPair(t *testing.T, notAfter time.Time, names ...string) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := x509.MarshalECPrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})
}

func body(t *testing.T, s *Server, path string, cookies []*http.Cookie) string {
	t.Helper()
	resp := get(t, s, path, cookies)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s returned %d", path, resp.StatusCode)
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func errorOf(resp *httptest.ResponseRecorder) string {
	location := resp.Header().Get("Location")
	if !strings.HasPrefix(location, "/domains?error=") {
		return ""
	}
	message, _ := url.QueryUnescape(strings.TrimPrefix(location, "/domains?error="))
	return message
}

func TestSiteAddress(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:3000":           "http://127.0.0.1:3000",
		"http://203.0.113.7:8080":  "http://203.0.113.7:8080",
		"https://10.0.0.5":         "https://10.0.0.5",
		" backend ":                "http://backend",
		"http://backend/":          "http://backend",
		"2001:db8::1":              "http://[2001:db8::1]",
		"https://[2001:db8::1]:84": "https://[2001:db8::1]:84",
	}
	for in, want := range cases {
		if got := siteAddress(in); got != want {
			t.Errorf("siteAddress(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTheDomainsPageIsBehindALogin(t *testing.T) {
	s, _ := newDomainsServer(t)
	if resp := get(t, s, "/domains", nil); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("/domains without a login returned %d", resp.StatusCode)
	}
	for _, path := range []string{"/domains/add", "/domains/remove", "/domains/certificate"} {
		resp := postForm(t, s, path, nil, url.Values{"host": {"x.ru"}, "server": {"127.0.0.1"}})
		if resp.Code != http.StatusSeeOther || !strings.HasPrefix(resp.Header().Get("Location"), "/login") {
			t.Errorf("%s without a login returned %d to %q", path, resp.Code, resp.Header().Get("Location"))
		}
	}
	if len(s.o.Domains.List()) != 0 {
		t.Error("something was written without a login")
	}
}

func TestAddingAndRemovingADomain(t *testing.T) {
	s, _ := newDomainsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	// Without the token: a request that did not come from our page.
	resp := postForm(t, s, "/domains/add", cookies, url.Values{
		"host": {"here.example.ru"}, "server": {"127.0.0.1:8080"},
	})
	if resp.Code != http.StatusForbidden {
		t.Errorf("an add without a token returned %d, want 403", resp.Code)
	}

	resp = postForm(t, s, "/domains/add", cookies, url.Values{
		"csrf": {csrf}, "host": {"Here.Example.RU"}, "server": {"127.0.0.1:8080"},
	})
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/domains" {
		t.Fatalf("the add returned %d to %q", resp.Code, resp.Header().Get("Location"))
	}
	if list := s.o.Domains.List(); len(list) != 1 || list[0].Host != "here.example.ru" ||
		list[0].To != "http://127.0.0.1:8080" {
		t.Fatalf("the file holds %+v", list)
	}

	postForm(t, s, "/domains/add", cookies, url.Values{
		"csrf": {csrf}, "host": {"away.example.ru"}, "server": {"https://2001:db8::1"},
	})
	if to := s.o.Domains.Routes()["away.example.ru"]; to != "https://[2001:db8::1]" {
		t.Errorf("the IPv6 address was written as %q", to)
	}

	page := body(t, s, "/domains", cookies)
	for _, piece := range []string{
		"here.example.ru", "http://127.0.0.1:8080", "added here",
		"hand.example.ru", "configuration", "points here", "points at 198.51.100.20",
		"no address in DNS", "self-signed", "http://backend",
	} {
		if !strings.Contains(page, piece) {
			t.Errorf("the domains page does not contain %q", piece)
		}
	}
	if strings.Contains(page, "style=") {
		t.Error("the domains page carries a style attribute, which the CSP forbids")
	}

	resp = postForm(t, s, "/domains/remove", cookies, url.Values{"csrf": {csrf}, "host": {"here.example.ru"}})
	if resp.Code != http.StatusSeeOther {
		t.Fatalf("the removal returned %d", resp.Code)
	}
	if _, ok := s.o.Domains.Routes()["here.example.ru"]; ok {
		t.Error("the domain stayed after removal")
	}
}

// What the admin UI refuses comes back to the human as a message.
func TestDomainRefusalsAreShown(t *testing.T) {
	s, _ := newDomainsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	cases := []url.Values{
		{"host": {"*"}, "server": {"127.0.0.1"}},
		{"host": {"a.ru"}, "server": {"ftp://127.0.0.1"}},
		{"host": {"a.ru"}, "server": {""}},
		{"host": {"a.ru"}, "server": {"1.2.3.4/path"}},
	}
	for _, form := range cases {
		form.Set("csrf", csrf)
		if errorOf(postForm(t, s, "/domains/add", cookies, form)) == "" {
			t.Errorf("%v: no error came back", form)
		}
	}
	if n := len(s.o.Domains.List()); n != 0 {
		t.Errorf("refused forms wrote %d domains", n)
	}

	// Removing a configuration route is impossible: it is not in the file.
	resp := postForm(t, s, "/domains/remove", cookies, url.Values{"csrf": {csrf}, "host": {"hand.example.ru"}})
	if errorOf(resp) == "" {
		t.Error("removing a configuration route did not say it cannot")
	}
}

// The domain is taken from the certificate itself: the form asks only
// for the two files.
func TestUploadingACertificate(t *testing.T) {
	s, dir := newDomainsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	chain, key := pemPair(t, time.Now().AddDate(0, 3, 0), "hand.example.ru")

	if resp := upload(t, s, cookies, "", chain, key); resp.Code != http.StatusForbidden {
		t.Errorf("an upload without a token returned %d, want 403", resp.Code)
	}
	if s.o.Certs.Covering("hand.example.ru") != nil {
		t.Fatal("the certificate got in without a token")
	}

	resp := upload(t, s, cookies, csrf, chain, key)
	if resp.Code != http.StatusSeeOther || resp.Header().Get("Location") != "/domains" {
		t.Fatalf("the upload returned %d to %q (%s)", resp.Code, resp.Header().Get("Location"), errorOf(resp))
	}
	// It serves at once, without waiting for the rescan timer.
	if s.o.Certs.Covering("hand.example.ru") == nil {
		t.Fatal("the uploaded certificate does not serve")
	}
	if _, err := os.Stat(filepath.Join(dir, "certificates", "hand.example.ru", "fullchain.pem")); err != nil {
		t.Errorf("the pair is not where the domain says: %v", err)
	}
	if page := body(t, s, "/domains", cookies); strings.Contains(page, "d left") {
		t.Error("a certificate for three months is shown as expiring")
	}
}

// One wildcard certificate serves every served name it fits, and lands
// once.
func TestAWildcardCertificateCoversItsServedNames(t *testing.T) {
	s, _ := newDomainsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	postForm(t, s, "/domains/add", cookies, url.Values{"csrf": {csrf}, "host": {"here.example.ru"}, "server": {"127.0.0.1"}})

	chain, key := pemPair(t, time.Now().AddDate(0, 3, 0), "*.example.ru")
	if resp := upload(t, s, cookies, csrf, chain, key); errorOf(resp) != "" {
		t.Fatalf("the wildcard pair was refused: %s", errorOf(resp))
	}
	for _, host := range []string{"hand.example.ru", "here.example.ru"} {
		if s.o.Certs.Covering(host) == nil {
			t.Errorf("%s is not covered by the wildcard", host)
		}
	}
	if n := s.o.Certs.Len(); n != 1 {
		t.Errorf("the pair landed %d times", n)
	}
}

func TestUploadRefusals(t *testing.T) {
	s, _ := newDomainsServer(t)
	cookies := logIn(t, s)
	csrf := tokenFrom(cookies)

	chain, _ := pemPair(t, time.Now().AddDate(0, 3, 0), "hand.example.ru")
	_, strangerKey := pemPair(t, time.Now().AddDate(0, 3, 0), "hand.example.ru")
	foreign, foreignKey := pemPair(t, time.Now().AddDate(0, 3, 0), "nobody.example.ru")

	cases := []struct {
		name       string
		chain, key []byte
		want       string
	}{
		{"a key that does not match", chain, strangerKey, "does not match"},
		{"a certificate only for names the node does not serve", foreign, foreignKey, "serves none"},
		{"not PEM at all", []byte("hello"), []byte("world"), "no certificate"},
	}
	for _, c := range cases {
		if got := errorOf(upload(t, s, cookies, csrf, c.chain, c.key)); !strings.Contains(got, c.want) {
			t.Errorf("%s: the message is %q, want one mentioning %q", c.name, got, c.want)
		}
	}
	if s.o.Certs.Len() != 0 {
		t.Error("a refused pair got into the set")
	}
}

// There is no auto-renewal, so the overview must say when a
// certificate is about to run out.
func TestTheOverviewWarnsAboutAnExpiringCertificate(t *testing.T) {
	s, _ := newDomainsServer(t)
	cookies := logIn(t, s)

	chain, key := pemPair(t, time.Now().Add(5*24*time.Hour+time.Hour), "hand.example.ru")
	if resp := upload(t, s, cookies, tokenFrom(cookies), chain, key); errorOf(resp) != "" {
		t.Fatalf("the upload was refused: %s", errorOf(resp))
	}

	page := body(t, s, "/", cookies)
	if !strings.Contains(page, `class="warning"`) || !strings.Contains(page, "expires in 5 days") {
		t.Error("the overview does not warn about a certificate expiring in five days")
	}
	if !strings.Contains(body(t, s, "/domains", cookies), "5 d left") {
		t.Error("the domains page does not mark the expiring certificate")
	}
}
