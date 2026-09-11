// Package domains keeps the domains added while the node runs: which
// host is served and where its site lives.
//
// The domains from the configuration are not here on purpose: config.yaml
// belongs to the machine's owner and the node never writes it. This file
// has exactly two writers — `antibot domains` and the admin UI — and both
// go through the same validation and the same atomic replacement, the way
// rules.json works. On a name both sources know, the configuration wins:
// what the machine's owner wrote by hand must not be overridden by a
// stolen admin UI session.
package domains

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/hostnorm"
)

// Domain is one served name.
type Domain struct {
	// Host is the name the clients come with: an exact name or a
	// "*.example.ru" pattern. The bare "*" is not accepted: the default
	// route decides what the node answers to made-up names, and that
	// stays in the configuration, with the machine's owner.
	Host string `json:"host"`

	// To is the address of the site's server: scheme, host, optional
	// port — "http://203.0.113.7:8080". The Host header is passed as is.
	// Loopback and private networks are fine: the site often lives on
	// the same machine.
	To string `json:"to"`
}

// File is the contents of domains.json.
type File struct {
	Version int      `json:"version"`
	Domains []Domain `json:"domains"`
}

// FormatVersion is the current version of the domains file.
const FormatVersion = 1

// NormalizeHost validates a served name and brings it to the single
// form the router and the certificates use.
func NormalizeHost(host string) (string, error) {
	h := strings.TrimSpace(host)
	if h == "" {
		return "", errors.New("empty host")
	}
	if h == "*" {
		return "", errors.New(`the default route "*" is set in the configuration, not here`)
	}
	pattern := strings.HasPrefix(h, "*.")
	if pattern {
		h = h[2:]
	}
	n := hostnorm.Normalize(h)
	if n == "" || strings.ContainsAny(n, "*/\\ ") {
		return "", fmt.Errorf("%q does not look like a host name", host)
	}
	if pattern {
		return "*." + n, nil
	}
	return n, nil
}

// checkTo validates the address of the site's server.
func checkTo(to string) error {
	u, err := url.Parse(to)
	if err != nil {
		return fmt.Errorf("address %q: %w", to, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("address %q: the scheme is http or https", to)
	}
	if u.Host == "" {
		return fmt.Errorf("address %q: no server in it", to)
	}
	if u.User != nil {
		return fmt.Errorf("address %q: credentials do not belong in it", to)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("address %q: only scheme, server and port — without a path", to)
	}
	return nil
}

// Validate checks the list as a whole: each entry and the absence of
// duplicates. It changes nothing — the caller normalizes.
func Validate(list []Domain) error {
	seen := make(map[string]struct{}, len(list))
	for i, d := range list {
		normalized, err := NormalizeHost(d.Host)
		if err != nil {
			return fmt.Errorf("domains[%d]: %w", i, err)
		}
		if normalized != d.Host {
			return fmt.Errorf("domains[%d]: %q is written down as %q", i, d.Host, normalized)
		}
		if err := checkTo(d.To); err != nil {
			return fmt.Errorf("domains[%d] (%s): %w", i, d.Host, err)
		}
		if _, ok := seen[d.Host]; ok {
			return fmt.Errorf("the domain %q is listed twice", d.Host)
		}
		seen[d.Host] = struct{}{}
	}
	return nil
}

// Store holds the current list and rereads the file when it changes.
type Store struct {
	path string
	log  *slog.Logger

	// The snapshot lives behind a pointer: the router is rebuilt from it
	// on every change, and readers must never see a half-written list.
	list atomic.Pointer[[]Domain]

	// onChange is called after every successful reload or write. The
	// node hooks the router rebuild here.
	onChange atomic.Pointer[func()]

	mu      sync.Mutex // guards the file's metadata and the writing
	modTime time.Time
	size    int64
	existed bool
}

// Open reads the domains file. An absent file is not an error: a node
// whose domains all live in the configuration is an ordinary node.
func Open(path string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{path: path, log: log}
	empty := []Domain{}
	s.list.Store(&empty)

	if _, err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// List is the domains currently in force, in the order of the file.
func (s *Store) List() []Domain {
	current := *s.list.Load()
	out := make([]Domain, len(current))
	copy(out, current)
	return out
}

// Routes hands the list to the router as "name → address" pairs.
func (s *Store) Routes() map[string]string {
	current := *s.list.Load()
	out := make(map[string]string, len(current))
	for _, d := range current {
		out[d.Host] = d.To
	}
	return out
}

// OnChange sets the callback called after every successful reload or
// write. One callback is enough: the only listener is the router.
func (s *Store) OnChange(f func()) { s.onChange.Store(&f) }

func (s *Store) changed() {
	if f := s.onChange.Load(); f != nil {
		(*f)()
	}
}

// Path is the path to the domains file.
func (s *Store) Path() string { return s.path }

// Watch rereads the file for as long as the context lives. By mtime and
// size, the same way the rules are watched.
func (s *Store) Watch(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := s.reload()
			if err != nil {
				// The previous list stays in force: a broken file must
				// not take the served sites off the air.
				s.log.Error("the domains were not reread, the previous list is in force",
					"file", s.path, "err", err)
				continue
			}
			if changed {
				s.log.Info("the domains were reread", "file", s.path, "domains", len(*s.list.Load()))
			}
		}
	}
}

// reload reads the file if it has changed. It returns whether it changed.
func (s *Store) reload() (bool, error) {
	s.mu.Lock()
	changed, err := s.reloadLocked()
	s.mu.Unlock()
	if changed {
		s.changed()
	}
	return changed, err
}

func (s *Store) reloadLocked() (bool, error) {
	info, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !s.existed {
			return false, nil
		}
		// The file existed and is gone: a human's decision, not a
		// failure. The domains from the configuration keep working.
		empty := []Domain{}
		s.list.Store(&empty)
		s.existed, s.modTime, s.size = false, time.Time{}, 0
		return true, nil
	case err != nil:
		return false, fmt.Errorf("domains %s: %w", s.path, err)
	}

	if s.existed && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return false, nil
	}

	contents, err := os.ReadFile(s.path)
	if err != nil {
		return false, fmt.Errorf("domains %s: %w", s.path, err)
	}
	list, err := Parse(contents)
	if err != nil {
		return false, fmt.Errorf("domains %s: %w", s.path, err)
	}

	s.list.Store(&list)
	s.existed, s.modTime, s.size = true, info.ModTime(), info.Size()
	return true, nil
}

// Parse parses the contents of a domains file and validates the list.
func Parse(contents []byte) ([]Domain, error) {
	var f File
	decoder := json.NewDecoder(bytes.NewReader(contents))
	// A typo in a field name is an error, not a silently skipped
	// intention.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("version %d, and the node understands %d", f.Version, FormatVersion)
	}
	if err := Validate(f.Domains); err != nil {
		return nil, err
	}
	return f.Domains, nil
}

// Read reads the domains from a file without touching the list in
// force. Needed by whatever edits the file: add, remove.
func Read(path string) ([]Domain, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	list, err := Parse(contents)
	if err != nil {
		return nil, fmt.Errorf("domains %s: %w", path, err)
	}
	return list, nil
}

// Write replaces the domains file as a whole — through a temporary file
// and a rename, the same way the rules are written.
func (s *Store) Write(list []Domain) error {
	if err := Validate(list); err != nil {
		return err
	}

	contents, err := json.MarshalIndent(File{Version: FormatVersion, Domains: list}, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	s.mu.Lock()
	err = func() error {
		defer s.mu.Unlock()

		dir := filepath.Dir(s.path)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return fmt.Errorf("domains directory: %w", err)
		}
		tmp, err := os.CreateTemp(dir, ".domains-*.json")
		if err != nil {
			return err
		}
		name := tmp.Name()
		defer os.Remove(name)

		if _, err := tmp.Write(contents); err != nil {
			tmp.Close()
			return err
		}
		// Sync before the rename: after a power cut a zero-length file
		// in place of the domains would take every added site off the
		// air at once.
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Chmod(name, 0o640); err != nil {
			return err
		}
		if err := os.Rename(name, s.path); err != nil {
			return err
		}

		// Reread at once without waiting for the watcher: a human who
		// has just added a domain must see it served.
		_, err = s.reloadLocked()
		return err
	}()
	if err != nil {
		return err
	}
	s.changed()
	return nil
}

// Add puts one domain in. The file is read anew rather than taken from
// the snapshot: it may have been edited by hand meanwhile.
func (s *Store) Add(host, to string) (Domain, error) {
	normalized, err := NormalizeHost(host)
	if err != nil {
		return Domain{}, err
	}
	if err := checkTo(to); err != nil {
		return Domain{}, err
	}

	list, err := Read(s.path)
	if err != nil {
		return Domain{}, err
	}
	for _, d := range list {
		if d.Host == normalized {
			return Domain{}, fmt.Errorf("the domain %q is already there", normalized)
		}
	}
	added := Domain{Host: normalized, To: to}
	return added, s.Write(append(list, added))
}

// Remove takes one domain out.
func (s *Store) Remove(host string) error {
	normalized, err := NormalizeHost(host)
	if err != nil {
		return err
	}

	list, err := Read(s.path)
	if err != nil {
		return err
	}
	left := make([]Domain, 0, len(list))
	for _, d := range list {
		if d.Host != normalized {
			left = append(left, d)
		}
	}
	if len(left) == len(list) {
		return fmt.Errorf("there is no domain %q", normalized)
	}
	return s.Write(left)
}
