package edgetls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Install validates an uploaded certificate pair and puts it into the
// upload directory in the certbot layout: a subdirectory per domain,
// fullchain.pem and privkey.pem, the key with 0600. The scanner then
// picks it up like any other pair.
//
// The checks are the point: a key that does not match, a certificate
// without the domain's name or one already expired is a refusal with a
// clear reason, and the previous certificate stays in force — the same
// way a broken rules file leaves the previous set working.
func Install(dir, host string, chain, key []byte) (time.Time, error) {
	if dir == "" {
		return time.Time{}, fmt.Errorf("there is nowhere to put uploaded certificates: tls.uploaded_dir is empty")
	}

	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return time.Time{}, fmt.Errorf("the pair was not accepted: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return time.Time{}, fmt.Errorf("the certificate was not parsed: %w", err)
		}
	}

	if !Fits(leaf, host) {
		return time.Time{}, fmt.Errorf("the certificate does not fit %s: it is for %s",
			host, strings.Join(LeafNames(leaf), ", "))
	}

	now := time.Now()
	if now.After(leaf.NotAfter) {
		return time.Time{}, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("02.01.2006"))
	}
	if now.Before(leaf.NotBefore) {
		return time.Time{}, fmt.Errorf("the certificate is not valid until %s", leaf.NotBefore.Format("02.01.2006"))
	}

	// "*" cannot be a directory name everywhere, and the scanner takes
	// the names from the certificate anyway.
	sub := filepath.Join(dir, strings.Replace(host, "*.", "_wildcard.", 1))
	if err := os.MkdirAll(sub, 0o750); err != nil {
		return time.Time{}, fmt.Errorf("certificate directory: %w", err)
	}

	// The key goes first and the certificate second: the scanner treats
	// an inconsistent pair as "being replaced" and keeps the previous
	// one, so no order breaks anything — but a readable certificate with
	// a missing key would be the state left behind by a failure between
	// the two writes.
	if err := replaceFile(filepath.Join(sub, "privkey.pem"), key, 0o600); err != nil {
		return time.Time{}, err
	}
	if err := replaceFile(filepath.Join(sub, "fullchain.pem"), chain, 0o644); err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// Fits answers whether the certificate serves the host. A
// "*.example.ru" entry needs exactly that wildcard name: a wildcard
// covers one label, and pretending otherwise breaks the handshake later,
// at the worst moment.
func Fits(leaf *x509.Certificate, host string) bool {
	if strings.HasPrefix(host, "*.") {
		for _, name := range leaf.DNSNames {
			if strings.EqualFold(name, host) {
				return true
			}
		}
		return false
	}
	return leaf.VerifyHostname(host) == nil
}

// LeafNames takes the names from the certificate itself: the DNS names,
// or the common name when there are none.
func LeafNames(leaf *x509.Certificate) []string {
	out := make([]string, 0, len(leaf.DNSNames)+1)
	for _, name := range leaf.DNSNames {
		out = append(out, strings.ToLower(name))
	}
	if len(out) == 0 && leaf.Subject.CommonName != "" {
		out = append(out, strings.ToLower(leaf.Subject.CommonName))
	}
	return out
}

// replaceFile writes atomically: a temporary file, sync, rename.
func replaceFile(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}
