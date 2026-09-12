package rules

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

// File is the contents of rules.json.
type File struct {
	// Version is for the future: the format will have to change, and the
	// node will need to say so clearly rather than parse a foreign file
	// by guesswork.
	Version int    `json:"version"`
	Rules   []Rule `json:"rules"`
}

// FormatVersion is the current version of the rules file.
const FormatVersion = 1

// Store holds the compiled set and rereads the file when it changes.
type Store struct {
	path    string
	limiter Limiter
	log     *slog.Logger

	// The snapshot lives behind a pointer: the hot path reads it without
	// a lock, and a reload swaps it whole. Rules change once a day and
	// are read on every request.
	set atomic.Pointer[Set]

	mu      sync.Mutex // guards the file's metadata and the writing
	modTime time.Time
	size    int64
	existed bool
}

// Open reads the rules file. An absent file is not an error: a node
// without rules works and proxies, and that is its ordinary state right
// after installation.
func Open(path string, limiter Limiter, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{path: path, limiter: limiter, log: log}

	empty, err := Build(nil, limiter)
	if err != nil {
		return nil, err
	}
	s.set.Store(empty)

	if _, err := s.reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Set is the set currently in force.
func (s *Store) Set() *Set { return s.set.Load() }

// Decide is what it is all for: a Store is the decider for the handler.
func (s *Store) Decide(r *facts.Request) proxy.Decision {
	return s.set.Load().Decide(r)
}

// Watch rereads the file for as long as the context lives.
//
// By mtime and size rather than by inotify: what has to be watched is a
// single file changed once a day, and inotify would add one more way to
// break — with a queue overflow and a lost event.
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
				// The previous set stays in force. A broken file must
				// neither bring the node down nor silently lift the
				// protection.
				s.log.Error("the rules were not reread, the previous set is in force",
					"file", s.path, "err", err)
				continue
			}
			if changed {
				s.log.Info("the rules were reread",
					"file", s.path, "in_force", len(s.set.Load().Effective()))
			}
		}
	}
}

// reload reads the file if it has changed. It returns whether it changed.
func (s *Store) reload() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reloadLocked()
}

func (s *Store) reloadLocked() (bool, error) {
	info, err := os.Stat(s.path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !s.existed {
			return false, nil
		}
		// The file existed and is gone. The rules are lifted: a vanished
		// file is a human's decision rather than a failure, and
		// pretending it is still there is not allowed.
		empty, err := Build(nil, s.limiter)
		if err != nil {
			return false, err
		}
		s.set.Store(empty)
		s.existed, s.modTime, s.size = false, time.Time{}, 0
		return true, nil
	case err != nil:
		return false, fmt.Errorf("rules %s: %w", s.path, err)
	}

	if s.existed && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return false, nil
	}

	contents, err := os.ReadFile(s.path)
	if err != nil {
		return false, fmt.Errorf("rules %s: %w", s.path, err)
	}
	set, err := Parse(contents, s.limiter)
	if err != nil {
		return false, fmt.Errorf("rules %s: %w", s.path, err)
	}

	s.set.Store(set)
	s.existed, s.modTime, s.size = true, info.ModTime(), info.Size()
	return true, nil
}

// Parse parses the contents of a rules file and builds the set.
func Parse(contents []byte, limiter Limiter) (*Set, error) {
	var f File
	decoder := json.NewDecoder(bytes.NewReader(contents))
	// A typo in a field name is an error, not a silently skipped
	// intention: whoever wrote "enable" instead of "enabled" finds out
	// right away rather than during an incident post-mortem.
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("parsing: %w", err)
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("version %d, and the node understands %d", f.Version, FormatVersion)
	}
	return Build(f.Rules, limiter)
}

// Write replaces the rules file as a whole.
//
// Through a temporary file and a rename: reading and writing go at the
// same time — the node rereads the file while a human edits it — and
// seeing half of a written file must not be possible.
func (s *Store) Write(rules []Rule) error {
	// A check before the write: do not let a set be written that the node
	// itself would later refuse to read.
	if _, err := Build(rules, s.limiter); err != nil {
		return err
	}

	contents, err := json.MarshalIndent(File{Version: FormatVersion, Rules: rules}, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("rules directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".rules-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	// Clean up after ourselves if it never got as far as the rename.
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	// Sync before the rename: otherwise after a power cut a file of zero
	// length ends up in place of the rules — a rename survives a failure,
	// unflushed contents do not.
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

	// Reread at once without waiting for the watcher: a human who has
	// just enabled a rule must see it in action.
	_, err = s.reloadLocked()
	return err
}

// Path is the path to the rules file.
func (s *Store) Path() string { return s.path }

// Toggle enables or disables a rule.
//
// Toggle and SetMode are the changes to the rules available from outside
// the command line: the admin UI may enable, disable and move between
// shadow and active what has already been written, but not compose
// anything new. Both go through the same write and the same validation
// as `antibot rules` — there is no second path to rules.json.
func (s *Store) Toggle(id string, enable bool) error {
	return s.change(id, func(r *Rule) {
		value := enable
		r.Enabled = &value
	})
}

// SetMode moves a rule between shadow and active. A rule is born in
// shadow; this is the step a human takes after looking at whom it
// touches — and the step a proposal from the cloud never takes.
func (s *Store) SetMode(id, mode string) error {
	if mode != Shadow && mode != Active {
		return fmt.Errorf("mode %q: it is %s or %s", mode, Shadow, Active)
	}
	return s.change(id, func(r *Rule) { r.Mode = mode })
}

// change edits one rule and writes the file.
func (s *Store) change(id string, edit func(*Rule)) error {
	// The file is read anew rather than taken from the in-memory
	// snapshot: it may have been edited by hand, and writing over a stale
	// snapshot would silently undo somebody else's changes.
	list, err := Read(s.path)
	if err != nil {
		return err
	}

	found := false
	for i := range list {
		if list[i].ID == id {
			edit(&list[i])
			found = true
		}
	}
	if !found {
		return fmt.Errorf("there is no rule %q", id)
	}
	return s.Write(list)
}

// Read reads the rules from a file without touching the set in force.
// Needed by the subcommands that edit the file: add, enable, disable.
func Read(path string) ([]Rule, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return nil, fmt.Errorf("rules %s: %w", path, err)
	}
	if f.Version != FormatVersion {
		return nil, fmt.Errorf("rules %s: version %d, and the node understands %d", path, f.Version, FormatVersion)
	}
	return f.Rules, nil
}
