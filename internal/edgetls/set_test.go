package edgetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// putCertificate places a subdirectory with a pair of files per domain
// into the directory.
func putCertificate(t *testing.T, dir, domain string, names []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	sub := filepath.Join(dir, domain)
	if err := os.MkdirAll(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(filepath.Join(sub, "fullchain.pem"), "CERTIFICATE", der, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writePEM(filepath.Join(sub, "privkey.pem"), "EC PRIVATE KEY", keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, s *Set, sni string) *tls.Certificate {
	t.Helper()
	c, err := s.Get(&tls.ClientHelloInfo{ServerName: sni})
	if err != nil {
		t.Fatalf("no certificate was picked for %q: %v", sni, err)
	}
	return c
}

func TestSelectionBySNI(t *testing.T) {
	dir := t.TempDir()
	putCertificate(t, dir, "shop.example.ru", []string{"shop.example.ru"})
	putCertificate(t, dir, "wild", []string{"*.example.com"})

	fallback, err := SelfSigned(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := Open(dir, fallback, nil)

	if c := get(t, s, "shop.example.ru"); c.Leaf.Subject.CommonName != "shop.example.ru" {
		t.Errorf("exact name: picked %q", c.Leaf.Subject.CommonName)
	}
	// A wildcard covers exactly one label.
	if c := get(t, s, "api.example.com"); c.Leaf.Subject.CommonName != "wild" {
		t.Errorf("*.example.com: picked %q", c.Leaf.Subject.CommonName)
	}
	if c := get(t, s, "a.b.example.com"); c.Leaf.Subject.CommonName == "wild" {
		t.Error("the wildcard covered two labels — the handshake will break")
	}
	// An unknown name goes to the fallback rather than tearing the
	// handshake down.
	if c := get(t, s, "foreign.site"); c != fallback {
		t.Error("an unknown name did not go to the fallback certificate")
	}
}

// A new domain is picked up without a restart — that is what the
// directory is rescanned for.
func TestANewDomainIsPickedUpWithoutARestart(t *testing.T) {
	dir := t.TempDir()
	s := Open(dir, nil, nil)

	if _, err := s.Get(&tls.ClientHelloInfo{ServerName: "new.example.ru"}); err == nil {
		t.Fatal("a certificate was found before it was put there")
	}

	putCertificate(t, dir, "new.example.ru", []string{"new.example.ru"})
	s.Reload()

	if c := get(t, s, "new.example.ru"); c.Leaf.Subject.CommonName != "new.example.ru" {
		t.Errorf("picked %q", c.Leaf.Subject.CommonName)
	}
}

// An unreachable directory must not discard the already loaded
// certificates: the site has to work while the human fixes the disk.
func TestAnUnreachableDirectoryDoesNotDiscardTheSet(t *testing.T) {
	dir := t.TempDir()
	putCertificate(t, dir, "shop.example.ru", []string{"shop.example.ru"})
	s := Open(dir, nil, nil)
	before := get(t, s, "shop.example.ru")

	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	s.Reload()

	after := get(t, s, "shop.example.ru")
	if before != after {
		t.Error("the set was discarded because of the vanished directory")
	}
}

// The self-signed certificate survives a restart: otherwise the site's
// fingerprint would change on every restart of the node.
func TestTheSelfSignedSurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	first, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SelfSigned(dir)
	if err != nil {
		t.Fatal(err)
	}

	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) != 0 {
		t.Error("a new certificate was issued on the second start")
	}

	st, err := os.Stat(filepath.Join(dir, "self-signed.key"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions %o, want 600", st.Mode().Perm())
	}
}
