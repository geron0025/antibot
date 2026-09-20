// Package cloudlink keeps what the owner answered about the cloud and
// the token the cloud gave back.
//
// It exists because the answer is the owner's, not the machine's. The
// settings file belongs to whoever installed the node — the admin UI
// never writes it, the same way it never writes the domains or the
// certificates into it — and yet "receive security updates" and "send
// statistics" are ticked in the admin UI, at the first login, by
// somebody who may never open a YAML file at all.
//
// So the answer lives here, in the node's own state, and the settings
// file wins wherever it says anything: what the machine's owner wrote by
// hand must not be overridden through a web page.
package cloudlink

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Format is the version of the file on disk.
const Format = 1

// State is the whole of what this package remembers.
//
// The token is in it, which is why the file is written readable by its
// owner only: it opens the bases and it names the installation to the
// cloud.
type State struct {
	Format int `json:"format"`

	// Answered says the owner has been asked. Without it a node that
	// was asked and said no to both is indistinguishable from one that
	// was never asked, and the first login would ask again at every
	// login.
	Answered bool `json:"answered"`

	// The two dates are pointers so that "never" is a missing line in
	// the file rather than the year zero: the file is read by people.
	AnsweredAt *time.Time `json:"answered_at,omitempty"`

	// Facts and Aggregates are the two checkboxes, in the order the
	// page shows them.
	Facts      bool `json:"facts"`
	Aggregates bool `json:"aggregates"`

	Token        string     `json:"token,omitempty"`
	Tenant       string     `json:"tenant,omitempty"`
	Level        string     `json:"level,omitempty"`
	FactsURL     string     `json:"facts_url,omitempty"`
	IngestURL    string     `json:"ingest_url,omitempty"`
	RegisteredAt *time.Time `json:"registered_at,omitempty"`
}

// Store is the file and what is in it.
type Store struct {
	path string
	log  *slog.Logger

	mu    sync.RWMutex
	state State

	changed []func()
}

// Open reads the file. A missing one is not an error: a node nobody has
// answered for yet is the normal state of a fresh installation.
func Open(path string, log *slog.Logger) (*Store, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Store{path: path, log: log, state: State{Format: Format}}
	if path == "" {
		return s, nil
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cloud state %s: %w", path, err)
	}

	var state State
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("cloud state %s: %w", path, err)
	}
	if state.Format != Format {
		return nil, fmt.Errorf("cloud state %s: format %d", path, state.Format)
	}
	s.state = state
	return s, nil
}

// State returns a copy: callers read it on every request, and handing
// out the original would make a lock of every read.
func (s *Store) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state
}

// Answer records what the owner ticked.
func (s *Store) Answer(facts, aggregates bool, now time.Time) error {
	return s.change(func(st *State) {
		st.Answered, st.AnsweredAt = true, &now
		st.Facts, st.Aggregates = facts, aggregates
	})
}

// Keep records the token and the addresses the cloud answered with.
//
// Written before the owner is told anything: a token that reached the
// node and was not written down is a tenant nobody can use, and the
// cloud will not issue a second one for the same installation.
func (s *Store) Keep(a Answer, now time.Time) error {
	return s.change(func(st *State) {
		st.Token, st.Tenant, st.Level = a.Token, a.Tenant, a.Level
		st.FactsURL, st.IngestURL = a.FactsURL, a.IngestURL
		st.RegisteredAt = &now
	})
}

// Forget drops the token. For the owner who wants the node to stop
// talking to the cloud at all: clearing the checkboxes stops the
// traffic, and this stops the node from being able to resume it.
func (s *Store) Forget() error {
	return s.change(func(st *State) {
		st.Token, st.Tenant, st.Level = "", "", ""
		st.FactsURL, st.IngestURL = "", ""
		st.RegisteredAt = nil
		st.Facts, st.Aggregates = false, false
	})
}

// OnChange registers a function to call after the state changes. The
// supervisor starts and stops the fetching and the sending by it.
func (s *Store) OnChange(fn func()) {
	s.mu.Lock()
	s.changed = append(s.changed, fn)
	s.mu.Unlock()
}

func (s *Store) change(apply func(*State)) error {
	s.mu.Lock()
	next := s.state
	next.Format = Format
	apply(&next)

	if err := s.write(next); err != nil {
		s.mu.Unlock()
		return err
	}
	s.state = next
	watchers := make([]func(), len(s.changed))
	copy(watchers, s.changed)
	s.mu.Unlock()

	for _, fn := range watchers {
		fn()
	}
	return nil
}

// write replaces the file whole: a state half written is a token half
// written, and the node would then have neither the old one nor a way
// to ask for a new one.
func (s *Store) write(state State) error {
	if s.path == "" {
		return errors.New("no file to keep the cloud state in")
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("cloud state: %w", err)
	}
	tmp := s.path + ".new"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("cloud state: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("cloud state: %w", err)
	}
	return nil
}
