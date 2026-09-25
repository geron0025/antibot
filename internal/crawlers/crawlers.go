// Package crawlers lets the verified crawlers past the owner's rules.
//
// A verified crawler is a network the fact set names a crawler's and
// marks protected: the ranges search engines, Google's checks and the
// chat assistants reading a page for a person publish about themselves.
// A request from one passes before any rule is looked at — like a
// request from the owner's own networks — and the event says so:
// "verified crawler". Blocking Googlebot by an oversight costs a site
// its place in the results; a rule written in a hurry must not do it.
//
// The pass is on by default, and it is the owner's to turn off: wholly,
// or for one owner of crawler networks — to keep a chat assistant out,
// say. The cloud only delivers the list of who is a verified crawler;
// what happens to them is decided here, by the node's owner.
//
// Without a fact set nobody is verified and nobody passes: a
// self-declared Googlebot from somebody else's network is a claim.
package crawlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// FormatVersion is the format version of the settings file.
const FormatVersion = 1

// MaxHeld bounds the list of owners held back.
const MaxHeld = 200

// Settings is what the owner decided.
type Settings struct {
	// Pass lets the verified crawlers past the rules. The default when
	// nothing was ever saved is true.
	Pass bool `json:"pass"`

	// Held are owners of crawler networks not let past: their requests
	// go through the rules like anybody's.
	Held []string `json:"held,omitempty"`

	UpdatedAt time.Time `json:"updated_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// Defaults is the pass as a node without a settings file has it.
func Defaults() Settings { return Settings{Pass: true} }

// Holds says whether an owner is held back.
func (s Settings) Holds(owner string) bool { return slices.Contains(s.Held, owner) }

type file struct {
	Version int `json:"version"`
	Settings
}

// File keeps the settings in the shared directory: the admin UI writes
// them, the core reads them. Mode 0640, like the rest of what the two
// programs share.
type File struct {
	path string

	mu      sync.Mutex
	modTime time.Time
	size    int64

	cur atomic.Pointer[Settings]
}

// Open reads the settings. A missing file is not an error: the pass is
// on and nobody is held.
func Open(path string) (*File, error) {
	f := &File{path: path}
	d := Defaults()
	f.cur.Store(&d)
	if _, err := f.Reload(); err != nil {
		return nil, err
	}
	return f, nil
}

// Reload rereads the file when it changed. On an error the settings in
// force stay: a file broken halfway through a hand edit must not turn
// the pass off or on by itself.
func (f *File) Reload() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, err := os.Stat(f.path)
	if errors.Is(err, fs.ErrNotExist) {
		changed := !f.modTime.IsZero()
		d := Defaults()
		f.cur.Store(&d)
		f.modTime, f.size = time.Time{}, 0
		return changed, nil
	}
	if err != nil {
		return false, fmt.Errorf("crawlers %s: %w", f.path, err)
	}
	if !f.modTime.IsZero() && info.ModTime().Equal(f.modTime) && info.Size() == f.size {
		return false, nil
	}
	contents, err := os.ReadFile(f.path)
	if err != nil {
		return false, fmt.Errorf("crawlers %s: %w", f.path, err)
	}
	var doc file
	if err := json.Unmarshal(contents, &doc); err != nil {
		return false, fmt.Errorf("crawlers %s: %w", f.path, err)
	}
	if doc.Version != FormatVersion {
		return false, fmt.Errorf("crawlers %s: version %d, and the node understands %d",
			f.path, doc.Version, FormatVersion)
	}
	s := doc.Settings
	f.cur.Store(&s)
	f.modTime, f.size = info.ModTime(), info.Size()
	return true, nil
}

// Get is the settings in force.
func (f *File) Get() Settings { return *f.cur.Load() }

// Passes is the hot path's question: a request from a verified crawler
// whose owner is not held back goes past the rules.
func (f *File) Passes(r *facts.Request) bool {
	if r.NetClass != "crawler" || !r.NetProtected {
		return false
	}
	s := f.cur.Load()
	return s.Pass && !s.Holds(r.NetOwner)
}

// Save replaces the settings.
func (f *File) Save(s Settings, by string, now time.Time) error {
	held := make([]string, 0, len(s.Held))
	for _, o := range s.Held {
		if o != "" && !slices.Contains(held, o) {
			held = append(held, o)
		}
	}
	if len(held) > MaxHeld {
		return fmt.Errorf("more than %d owners held back", MaxHeld)
	}
	sort.Strings(held)
	s.Held = held
	s.UpdatedAt, s.UpdatedBy = now.UTC().Truncate(time.Second), by

	contents, err := json.MarshalIndent(file{Version: FormatVersion, Settings: s}, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".crawlers-*.json")
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
	if err := os.Chmod(name, 0o640); err != nil {
		return err
	}
	if err := os.Rename(name, f.path); err != nil {
		return err
	}
	f.mu.Lock()
	f.modTime = time.Time{}
	f.mu.Unlock()
	_, err = f.Reload()
	return err
}
