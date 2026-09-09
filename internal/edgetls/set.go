// Package edgetls picks the certificate for the name the client stated in
// SNI.
//
// The certificate directory is rescanned on a timer, so a renewal by
// certbot and the addition of a new domain take effect without restarting
// the node.
//
// On a timer rather than by watching files: certificates are almost
// always updated by substitution — a rename on top or a symlink switch —
// and watching follows the inode and does not notice such a substitution
// at all.
package edgetls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Set keeps the certificates in memory and refreshes them in the
// background.
type Set struct {
	dir      string
	fallback *tls.Certificate
	log      *slog.Logger

	// The snapshot lives behind a pointer: the hot path reads it without
	// locks, and a refresh swaps it whole.
	current atomic.Pointer[snapshot]
}

type snapshot struct {
	byName map[string]*tls.Certificate
	byPath map[string]*tls.Certificate
	stamps map[string]stamp
}

// stamp is what a file substitution is noticed by: size and modification
// time.
type stamp struct {
	size    int64
	modTime time.Time
}

// Open builds the set from a directory. An empty or missing directory is
// not an error: a node with a single self-signed certificate must come
// up.
func Open(dir string, fallback *tls.Certificate, log *slog.Logger) *Set {
	if log == nil {
		log = slog.Default()
	}
	s := &Set{dir: dir, fallback: fallback, log: log}
	s.current.Store(&snapshot{
		byName: map[string]*tls.Certificate{},
		byPath: map[string]*tls.Certificate{},
		stamps: map[string]stamp{},
	})
	s.Reload()
	return s
}

// Watch rescans the directory on a timer until the channel is closed.
func (s *Set) Watch(interval time.Duration, stop <-chan struct{}) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.Reload()
		case <-stop:
			return
		}
	}
}

// Get returns the certificate for the name from SNI. It is plugged into
// tls.Config.GetCertificate.
func (s *Set) Get(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	snap := s.current.Load()
	name := strings.ToLower(strings.TrimSuffix(hi.ServerName, "."))

	if c, ok := snap.byName[name]; ok {
		return c, nil
	}

	// A wildcard in a certificate covers exactly one label:
	// *.example.ru fits shop.example.ru but not a.b.example.ru.
	if i := strings.IndexByte(name, '.'); i >= 0 {
		if c, ok := snap.byName["*"+name[i:]]; ok {
			return c, nil
		}
	}

	if s.fallback != nil {
		return s.fallback, nil
	}
	return nil, fmt.Errorf("no certificate for %q", hi.ServerName)
}

// Reload scans the directory and updates the snapshot if anything
// changed.
func (s *Set) Reload() {
	if s.dir == "" {
		return
	}

	pairs, err := findPairs(s.dir)
	if err != nil {
		// An unreachable directory does not discard the previous set: the
		// certificates in memory keep serving the site while the human
		// fixes the disk.
		s.log.Warn("the certificate directory was not read", "dir", s.dir, "err", err)
		return
	}

	old := s.current.Load()
	fresh := &snapshot{
		byName: make(map[string]*tls.Certificate, len(pairs)),
		byPath: make(map[string]*tls.Certificate, len(pairs)),
		stamps: make(map[string]stamp, len(pairs)),
	}

	for _, p := range pairs {
		st, err := fileStamp(p.cert)
		if err != nil {
			continue
		}
		fresh.stamps[p.cert] = st

		// The file has not changed — take the parsed certificate from the
		// previous snapshot instead of spending time on parsing PEM and
		// checking the key.
		if previous, ok := old.stamps[p.cert]; ok && previous == st {
			if kept, ok := old.byPath[p.cert]; ok {
				fresh.byPath[p.cert] = kept
				for _, name := range certificateNames(kept) {
					fresh.byName[name] = kept
				}
				continue
			}
		}

		cert, err := tls.LoadX509KeyPair(p.cert, p.key)
		if err != nil {
			// An inconsistent pair is an ordinary thing at the moment
			// files are being replaced: the update is not atomic. The
			// previous set stays in force meanwhile.
			s.log.Warn("the certificate was not loaded", "file", p.cert, "err", err)
			continue
		}
		if cert.Leaf == nil && len(cert.Certificate) > 0 {
			// Leaf is not filled in by the loader in every version of Go,
			// and without it the names cannot be taken from the
			// certificate.
			if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
				cert.Leaf = leaf
			}
		}
		fresh.byPath[p.cert] = &cert
		for _, name := range certificateNames(&cert) {
			fresh.byName[name] = &cert
		}
	}

	s.current.Store(fresh)
}

// certificateNames takes the names from the certificate itself rather
// than from the configuration. A second source of truth would drift apart
// from the certificate at the very first reissue — and would do so
// silently.
func certificateNames(c *tls.Certificate) []string {
	if c.Leaf == nil {
		return nil
	}
	out := make([]string, 0, len(c.Leaf.DNSNames)+1)
	for _, name := range c.Leaf.DNSNames {
		out = append(out, strings.ToLower(name))
	}
	if len(out) == 0 && c.Leaf.Subject.CommonName != "" {
		out = append(out, strings.ToLower(c.Leaf.Subject.CommonName))
	}
	return out
}

type pair struct{ cert, key string }

// findPairs understands two layouts: a subdirectory per domain with
// fullchain.pem and privkey.pem (the way certbot does it), or cert.pem
// and key.pem.
func findPairs(dir string) ([]pair, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var out []pair
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		sub := filepath.Join(dir, e.Name())
		for _, names := range [][2]string{
			{"fullchain.pem", "privkey.pem"},
			{"cert.pem", "key.pem"},
		} {
			cert := filepath.Join(sub, names[0])
			key := filepath.Join(sub, names[1])
			if fileExists(cert) && fileExists(key) {
				out = append(out, pair{cert: cert, key: key})
				break
			}
		}
	}
	return out, nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func fileStamp(path string) (stamp, error) {
	st, err := os.Stat(path)
	if err != nil {
		return stamp{}, err
	}
	return stamp{size: st.Size(), modTime: st.ModTime()}, nil
}
