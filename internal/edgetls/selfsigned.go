package edgetls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// SelfSigned returns a self-signed certificate, creating it on the first
// start and saving it into the directory.
//
// It exists so that the node comes up with no configuration at all:
// without it the very first HTTPS request would break off at the
// handshake, and whoever installed the container would decide it is
// broken. A browser complains about such a certificate, of course — and a
// warning about that is written to the log.
//
// Saving it matters no less than creating it: a certificate created anew
// on every start changes the site's fingerprint on every restart.
func SelfSigned(dir string) (*tls.Certificate, error) {
	if dir == "" {
		return create(nil)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("self-signed directory: %w", err)
	}

	cert := filepath.Join(dir, "self-signed.pem")
	key := filepath.Join(dir, "self-signed.key")

	if fileExists(cert) && fileExists(key) {
		c, err := tls.LoadX509KeyPair(cert, key)
		if err == nil {
			if c.Leaf == nil && len(c.Certificate) > 0 {
				c.Leaf, _ = x509.ParseCertificate(c.Certificate[0])
			}
			// An expired certificate is reissued: a year later it would
			// stop working as inconspicuously as it appeared.
			if c.Leaf == nil || time.Now().Before(c.Leaf.NotAfter) {
				return &c, nil
			}
		}
	}

	return create(&filePair{cert: cert, key: key})
}

type filePair struct{ cert, key string }

func create(to *filePair) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "antibot self-signed"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
	if to == nil {
		return cert, nil
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	// The key is written with mode 0600: it is the only thing here that
	// must be shown to nobody.
	if err := writePEM(to.key, "EC PRIVATE KEY", keyBytes, 0o600); err != nil {
		return nil, err
	}
	if err := writePEM(to.cert, "CERTIFICATE", der, 0o644); err != nil {
		return nil, err
	}
	return cert, nil
}

func writePEM(path, blockType string, body []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: blockType, Bytes: body})
}
