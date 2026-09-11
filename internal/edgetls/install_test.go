package edgetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pemPair issues a self-signed pair in PEM, the way an owner would
// bring it from certbot.
func pemPair(t *testing.T, names []string, notBefore, notAfter time.Time) (chain, key []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw})
}

func year() (time.Time, time.Time) {
	return time.Now().Add(-time.Hour), time.Now().AddDate(1, 0, 0)
}

func TestInstallPutsThePairWhereTheScannerLooks(t *testing.T) {
	dir := t.TempDir()
	from, until := year()
	chain, key := pemPair(t, []string{"shop.example.ru"}, from, until)

	got, err := Install(dir, "shop.example.ru", chain, key)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(until.Truncate(time.Second)) && got.Sub(until).Abs() > time.Second {
		t.Errorf("the term %v, want %v", got, until)
	}

	st, err := os.Stat(filepath.Join(dir, "shop.example.ru", "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("private key permissions %o, want 600", st.Mode().Perm())
	}

	s := Open([]string{dir}, nil, nil)
	if c := get(t, s, "shop.example.ru"); c.Leaf.Subject.CommonName != "shop.example.ru" {
		t.Errorf("the scanner picked %q", c.Leaf.Subject.CommonName)
	}
}

// Every refusal leaves the previous pair untouched: the site keeps
// being served while the human finds the right files.
func TestInstallRefusals(t *testing.T) {
	from, until := year()
	right, rightKey := pemPair(t, []string{"shop.example.ru"}, from, until)
	_, strangerKey := pemPair(t, []string{"shop.example.ru"}, from, until)
	other, otherKey := pemPair(t, []string{"other.example.ru"}, from, until)
	expired, expiredKey := pemPair(t, []string{"shop.example.ru"},
		time.Now().AddDate(-1, 0, 0), time.Now().Add(-time.Hour))
	wild, wildKey := pemPair(t, []string{"*.example.ru"}, from, until)

	cases := []struct {
		name       string
		host       string
		chain, key []byte
		want       string
	}{
		{"a key from another pair", "shop.example.ru", right, strangerKey, "not accepted"},
		{"a certificate for another name", "shop.example.ru", other, otherKey, "does not fit"},
		{"an expired certificate", "shop.example.ru", expired, expiredKey, "expired"},
		{"not PEM at all", "shop.example.ru", []byte("hello"), []byte("world"), "not accepted"},
		// A wildcard certificate fits a name, but a "*.x" entry needs
		// exactly the wildcard name: two labels deep it would not fit.
		{"a pattern without its wildcard name", "*.example.ru", right, rightKey, "does not fit"},
	}

	for _, c := range cases {
		dir := t.TempDir()
		if _, err := Install(dir, "shop.example.ru", right, rightKey); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(filepath.Join(dir, "shop.example.ru", "fullchain.pem"))

		_, err := Install(dir, c.host, c.chain, c.key)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error mentioning %q", c.name, err, c.want)
		}
		after, _ := os.ReadFile(filepath.Join(dir, "shop.example.ru", "fullchain.pem"))
		if string(before) != string(after) {
			t.Errorf("%s: the refused upload replaced the working pair", c.name)
		}
	}

	if _, err := Install(t.TempDir(), "*.example.ru", wild, wildKey); err != nil {
		t.Errorf("a wildcard pair for its pattern was refused: %v", err)
	}
	if _, err := Install("", "shop.example.ru", right, rightKey); err == nil {
		t.Error("an install without a directory did not say so")
	}
}

// When certbot's catalog and the uploads both hold a certificate for a
// name, the one that lives longer serves — the renewal wins whichever
// door it came through.
func TestTheLongerLivedCertificateWins(t *testing.T) {
	certbot, uploads := t.TempDir(), t.TempDir()
	from := time.Now().Add(-time.Hour)

	shortChain, shortKey := pemPair(t, []string{"shop.example.ru"}, from, time.Now().AddDate(0, 0, 5))
	if _, err := Install(certbot, "shop.example.ru", shortChain, shortKey); err != nil {
		t.Fatal(err)
	}
	longChain, longKey := pemPair(t, []string{"shop.example.ru"}, from, time.Now().AddDate(0, 3, 0))
	if _, err := Install(uploads, "shop.example.ru", longChain, longKey); err != nil {
		t.Fatal(err)
	}

	for _, order := range [][]string{{certbot, uploads}, {uploads, certbot}} {
		s := Open(order, nil, nil)
		c, err := s.Get(&tls.ClientHelloInfo{ServerName: "shop.example.ru"})
		if err != nil {
			t.Fatal(err)
		}
		if c.Leaf.NotAfter.Before(time.Now().AddDate(0, 2, 0)) {
			t.Errorf("directories %v: the short-lived certificate served", order)
		}
		if leaf := s.Covering("shop.example.ru"); leaf == nil || leaf.NotAfter != c.Leaf.NotAfter {
			t.Errorf("Covering disagrees with Get")
		}
	}
}

func TestCoveringAndList(t *testing.T) {
	dir := t.TempDir()
	from, until := year()
	chain, key := pemPair(t, []string{"*.example.ru"}, from, until)
	if _, err := Install(dir, "*.example.ru", chain, key); err != nil {
		t.Fatal(err)
	}
	s := Open([]string{dir}, nil, nil)

	if s.Covering("shop.example.ru") == nil {
		t.Error("the wildcard does not cover one label")
	}
	if s.Covering("a.b.example.ru") != nil {
		t.Error("the wildcard covered two labels")
	}
	if s.Covering("*.example.ru") == nil {
		t.Error("the pattern is not covered by its own wildcard")
	}
	if s.Covering("*.other.ru") != nil {
		t.Error("a foreign pattern is covered")
	}
	if list := s.List(); len(list) != 1 || list[0].Names[0] != "*.example.ru" {
		t.Errorf("List: %+v", list)
	}
}
