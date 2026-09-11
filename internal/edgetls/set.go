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
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Set keeps the certificates in memory and refreshes them in the
// background.
type Set struct {
	dirs     []string
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

// Open builds the set from directories — the catalog led by hand or by
// certbot, and the catalog of uploads. Empty or missing directories are
// not an error: a node with a single self-signed certificate must come
// up. When two files claim the same name, the certificate that lives
// longer wins: whichever way a renewal arrived, the fresh one serves.
func Open(dirs []string, fallback *tls.Certificate, log *slog.Logger) *Set {
	if log == nil {
		log = slog.Default()
	}
	kept := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if dir != "" {
			kept = append(kept, dir)
		}
	}
	s := &Set{dirs: kept, fallback: fallback, log: log}
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

// Reload scans the directories and updates the snapshot if anything
// changed.
func (s *Set) Reload() {
	if len(s.dirs) == 0 {
		return
	}

	var pairs []pair
	for _, dir := range s.dirs {
		found, err := findPairs(dir)
		if err != nil {
			// An unreachable directory does not discard the previous set:
			// the certificates in memory keep serving the site while the
			// human fixes the disk. A vanished directory counts too — an
			// unmounted volume must not take the sites off the air. The
			// upload directory is created at startup exactly so that its
			// absence never lands here.
			s.log.Warn("the certificate directory was not read", "dir", dir, "err", err)
			return
		}
		pairs = append(pairs, found...)
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
				claim(fresh, kept)
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
		claim(fresh, &cert)
	}

	s.current.Store(fresh)
}

// claim writes the certificate under its names. When two files claim
// the same name, the certificate that lives longer wins: whichever way
// a renewal arrived — certbot or an upload — the fresh one serves.
func claim(snap *snapshot, c *tls.Certificate) {
	for _, name := range certificateNames(c) {
		if existing, ok := snap.byName[name]; ok && notAfter(existing).After(notAfter(c)) {
			continue
		}
		snap.byName[name] = c
	}
}

func notAfter(c *tls.Certificate) time.Time {
	if c.Leaf != nil {
		return c.Leaf.NotAfter
	}
	return time.Time{}
}

// Info describes one loaded certificate — for the admin UI, which must
// show the owner what serves and when it expires.
type Info struct {
	Path     string
	Names    []string
	NotAfter time.Time
}

// List describes every loaded certificate, sorted by path.
func (s *Set) List() []Info {
	snap := s.current.Load()
	out := make([]Info, 0, len(snap.byPath))
	for path, c := range snap.byPath {
		out = append(out, Info{Path: path, Names: certificateNames(c), NotAfter: notAfter(c)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Covering returns the certificate that would serve the name, or nil
// when only the self-signed fallback would. The name may be a
// "*.example.ru" pattern — then the certificate must carry exactly that
// wildcard name.
func (s *Set) Covering(name string) *x509.Certificate {
	snap := s.current.Load()
	n := strings.ToLower(strings.TrimSuffix(name, "."))

	if c, ok := snap.byName[n]; ok {
		return c.Leaf
	}
	if strings.HasPrefix(n, "*.") {
		return nil
	}
	if i := strings.IndexByte(n, '.'); i >= 0 {
		if c, ok := snap.byName["*"+n[i:]]; ok {
			return c.Leaf
		}
	}
	return nil
}

// Len is how many certificates are loaded, the fallback not counted.
func (s *Set) Len() int { return len(s.current.Load().byPath) }

// certificateNames takes the names from the certificate itself rather
// than from the configuration. A second source of truth would drift apart
// from the certificate at the very first reissue — and would do so
// silently.
func certificateNames(c *tls.Certificate) []string {
	if c.Leaf == nil {
		return nil
	}
	return LeafNames(c.Leaf)
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
