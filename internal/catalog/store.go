package catalog

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// keep is how many versions stay on disk. Three, because a rollback has
// to be possible after the mistake was noticed rather than immediately,
// and because the disk of somebody else's server is not ours to fill.
const keep = 3

// ErrShrunk means the new set lost a large part of the previous one.
//
// A shrunken base is more dangerous than a stale one: a vanished row
// saying "do not touch this operator" turns a sensible rule into a block
// on live people, and from the outside it looks like "the site suddenly
// stopped opening".
var ErrShrunk = errors.New("the new set is much smaller than the one in force")

// Store keeps the applied set on disk and in memory.
type Store struct {
	dir     string
	enabled bool
	log     *slog.Logger
	keys    *Keyring

	// The set lives behind a pointer: the hot path reads it without a
	// lock, and applying a new one swaps the whole value.
	set atomic.Pointer[Set]

	mu sync.Mutex // guards the directory
}

// Open reads the applied set from disk.
//
// An empty or missing directory is not an error: a node that was never
// connected to anything has no set, and that is its normal state. Rules
// referring to unknown facts simply do not match; the rest work.
func Open(dir string, enabled bool, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{dir: dir, enabled: enabled, log: log, keys: NewKeyring()}

	if !enabled {
		// facts.enabled: false is the switch promised by the protocol.
		// It must turn the whole thing off, not merely stop the fetching:
		// a set already on disk keeps being applied otherwise.
		log.Info("fact set is switched off by the configuration")
		return s, nil
	}
	if dir == "" {
		return s, nil
	}

	if err := s.keys.LoadFile(filepath.Join(dir, "keys.json")); err != nil {
		// A bad key list must not stop the node: it works without facts.
		// But it must be loud — somebody either broke the file or is
		// trying to substitute a key.
		log.Error("the key list was not read, the built-in keys are in force", "err", err)
	}

	version, err := s.readCurrent()
	if err != nil || version == 0 {
		return s, nil
	}
	set, err := s.load(version)
	if err != nil {
		log.Error("the applied set was not read, working without facts",
			"version", version, "err", err)
		return s, nil
	}
	s.set.Store(set)
	log.Info("fact set applied", "version", set.Version(),
		"networks", set.networks, "fingerprints", len(set.fingerprints))
	return s, nil
}

// Current is the set in force. Nil means there is none.
func (s *Store) Current() *Set { return s.set.Load() }

// Apply fills the request in from the set in force. It is the hot path
// and it is what proxy.Handler calls.
func (s *Store) Apply(r *facts.Request) { s.set.Load().Apply(r) }

// Enabled reports whether the fact set is switched on at all.
func (s *Store) Enabled() bool { return s.enabled }

// Keyring is what the node believes. For the admin UI and for the loader.
func (s *Store) Keyring() *Keyring { return s.keys }

// Install runs every check the protocol requires and, if they all pass,
// puts the set into force.
//
// The order matters and is the order of the document: a set that failed
// any check leaves the previous one in force and writes to the log.
func (s *Store) Install(manifestRaw, setRaw []byte, force bool) (*Set, error) {
	if !s.enabled {
		return nil, fmt.Errorf("fact set is switched off by the configuration")
	}

	// 1. The manifest parses and names a key we trust.
	m, err := ParseManifest(manifestRaw)
	if err != nil {
		return nil, err
	}
	// 2. The signature verifies — with a key that signs sets, not
	//    proposals.
	if err := s.keys.Verify(m.KeyID, UseFacts, m.Digest(), m.Signature, time.Now()); err != nil {
		return nil, fmt.Errorf("manifest of version %d: %w", m.Version, err)
	}
	// 3. The version is higher than the current one — otherwise this is
	//    an attempt to roll back to a base somebody already replaced.
	if current := s.Current().Version(); m.Version <= current {
		return nil, fmt.Errorf("version %d is not above the current %d", m.Version, current)
	}
	// 4. The bytes are the ones the manifest describes.
	if err := m.Matches(setRaw); err != nil {
		return nil, err
	}
	// 5. The set parses whole and every record passes.
	set, err := Parse(setRaw)
	if err != nil {
		return nil, err
	}
	if set.Version() != m.Version {
		return nil, fmt.Errorf("the set says version %d, the manifest says %d", set.Version(), m.Version)
	}

	if err := s.checkShrink(set, force); err != nil {
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.MkdirAll(s.dir, 0o750); err != nil {
		return nil, fmt.Errorf("fact set directory: %w", err)
	}
	if err := writeAtomic(s.path(set.Version()), setRaw, 0o640); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(s.dir, "current"),
		[]byte(strconv.Itoa(set.Version())+"\n"), 0o640); err != nil {
		return nil, err
	}

	s.set.Store(set)
	s.sweep()

	networks, fingerprints, protected := set.Counts()
	s.log.Info("fact set applied", "version", set.Version(),
		"networks", networks, "fingerprints", fingerprints, "protected", protected)
	return set, nil
}

// checkShrink refuses a set that lost a large part of the previous one.
//
// Protected rows are weighted separately and not by accident: they are
// the most expensive thing in the base and the one whose loss is
// invisible until somebody's customers stop reaching the site.
func (s *Store) checkShrink(fresh *Set, force bool) error {
	current := s.Current()
	if current == nil || force {
		return nil
	}
	oldNets, _, oldProtected := current.Counts()
	newNets, _, newProtected := fresh.Counts()

	if oldNets > 0 && newNets*2 < oldNets {
		return fmt.Errorf("%w: networks %d instead of %d", ErrShrunk, newNets, oldNets)
	}
	if oldProtected > 0 && newProtected*2 < oldProtected {
		return fmt.Errorf("%w: protected rows %d instead of %d", ErrShrunk, newProtected, oldProtected)
	}
	return nil
}

// Rollback returns to the previous version kept on disk.
//
// No network is needed for this, and that is the point: a rollback is
// done when something is already broken, and depending on the cloud
// being reachable at that moment is not acceptable.
func (s *Store) Rollback() (*Set, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	versions := s.versions()
	current := s.Current().Version()

	var target int
	for _, v := range versions {
		if v < current && v > target {
			target = v
		}
	}
	if target == 0 {
		return nil, fmt.Errorf("there is no version to roll back to: on disk %v", versions)
	}

	set, err := s.load(target)
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(s.dir, "current"),
		[]byte(strconv.Itoa(target)+"\n"), 0o640); err != nil {
		return nil, err
	}
	s.set.Store(set)
	s.log.Warn("fact set rolled back", "from", current, "to", target)
	return set, nil
}

// Versions lists what is on disk, ascending.
func (s *Store) Versions() []int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.versions()
}

func (s *Store) path(version int) string {
	return filepath.Join(s.dir, strconv.Itoa(version)+".json")
}

func (s *Store) readCurrent() (int, error) {
	raw, err := os.ReadFile(filepath.Join(s.dir, "current"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(raw)))
}

func (s *Store) load(version int) (*Set, error) {
	raw, err := os.ReadFile(s.path(version))
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

func (s *Store) versions() []int {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") || name == "keys.json" {
			continue
		}
		if v, err := strconv.Atoi(strings.TrimSuffix(name, ".json")); err == nil {
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// sweep removes everything older than the last `keep` versions. Called
// under the lock.
func (s *Store) sweep() {
	versions := s.versions()
	if len(versions) <= keep {
		return
	}
	for _, v := range versions[:len(versions)-keep] {
		if err := os.Remove(s.path(v)); err != nil {
			s.log.Warn("an old set was not deleted", "version", v, "err", err)
		}
	}
}

func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".facts-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	// Sync before the rename: otherwise after a power cut a file of zero
	// length ends up in place of the base.
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
