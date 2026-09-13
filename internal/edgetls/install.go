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

	leaf, err := Validate(chain, key, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	if !Fits(leaf, host) {
		return time.Time{}, fmt.Errorf("the certificate does not fit %s: it is for %s",
			host, strings.Join(LeafNames(leaf), ", "))
	}

	// "*" cannot be a directory name everywhere, and the scanner takes
	// the names from the certificate anyway.
	sub := filepath.Join(dir, strings.Replace(host, "*.", "_wildcard.", 1))
	if err := writePair(filepath.Join(sub, "fullchain.pem"), filepath.Join(sub, "privkey.pem"), chain, key); err != nil {
		return time.Time{}, err
	}
	return leaf.NotAfter, nil
}

// InstallPair validates a pair and writes it over the files named — the
// admin UI's own certificate, whose place config.yaml names. No name is
// checked: the admin UI is reached by whatever name its owner gave it.
//
// A file that is a link is refused: certbot keeps its files as links into
// its archive, and replacing a link with a file would cut the renewal off
// without a word.
func InstallPair(certFile, keyFile string, chain, key []byte) (*x509.Certificate, error) {
	leaf, err := Validate(chain, key, time.Now())
	if err != nil {
		return nil, err
	}
	for _, path := range []string{certFile, keyFile} {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%s is a link, the way certbot keeps its files: renew it with certbot, not here", path)
		}
	}
	if err := writePair(certFile, keyFile, chain, key); err != nil {
		return nil, err
	}
	return leaf, nil
}

// Validate checks a pair the way every upload is checked: the key matches
// the certificate, and the term has begun and has not ended. Names are
// the caller's business: whose they must be depends on what the pair is
// for.
func Validate(chain, key []byte, now time.Time) (*x509.Certificate, error) {
	pair, err := tls.X509KeyPair(chain, key)
	if err != nil {
		return nil, fmt.Errorf("the pair was not accepted: %w", err)
	}
	leaf := pair.Leaf
	if leaf == nil {
		leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("the certificate was not parsed: %w", err)
		}
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("the certificate expired on %s", leaf.NotAfter.Format("02.01.2006"))
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("the certificate is not valid until %s", leaf.NotBefore.Format("02.01.2006"))
	}
	return leaf, nil
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

// writePair writes both files of a pair next to where they go first and
// only then renames them into place, the key before the certificate: a
// failure while writing leaves the previous pair whole, and the window in
// which the two files disagree is two renames long. A reader treats a
// pair that disagrees as "being replaced" and keeps the previous one.
func writePair(certFile, keyFile string, chain, key []byte) error {
	for _, path := range []string{certFile, keyFile} {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return fmt.Errorf("certificate directory: %w", err)
		}
	}
	keyTmp, err := writeTemp(keyFile, key, 0o600)
	if err != nil {
		return err
	}
	defer os.Remove(keyTmp)
	certTmp, err := writeTemp(certFile, chain, 0o644)
	if err != nil {
		return err
	}
	defer os.Remove(certTmp)

	if err := os.Rename(keyTmp, keyFile); err != nil {
		return err
	}
	return os.Rename(certTmp, certFile)
}

// writeTemp writes the contents into a temporary file next to path,
// synced and with its mode set, and returns the temporary file's name.
func writeTemp(path string, contents []byte, mode os.FileMode) (string, error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".upload-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return "", err
	}
	if err := os.Chmod(name, mode); err != nil {
		os.Remove(name)
		return "", err
	}
	return name, nil
}
