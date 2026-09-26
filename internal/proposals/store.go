package proposals

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/geron0025/antibot/internal/rules"
)

// DecisionsFileName is where the owner's decisions about proposals are
// kept, next to proposals.json and rules.json.
const DecisionsFileName = "proposal-decisions.json"

// decisionsFormat is the version of proposal-decisions.json.
const decisionsFormat = 1

// maxReasonRunes bounds the one piece of the owner's own text that
// leaves the node: docs/*/protocol/proposals.md caps the reason at 500
// runes on the wire, and it is refused here rather than truncated
// there, where he cannot see it happen.
const maxReasonRunes = 500

// Decision is what the owner did with one proposal.
type Decision struct {
	ID       string    `json:"id"`
	Accepted bool      `json:"accepted"`
	At       time.Time `json:"at"`
	Who      string    `json:"who,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

type decisionsFile struct {
	Format    int        `json:"format"`
	Decisions []Decision `json:"decisions"`
}

// AlreadyDecidedError names a proposal the owner already accepted or
// rejected. The admin UI does not offer a second decision on the same
// id, and this is the error a call that tries anyway gets back.
type AlreadyDecidedError struct {
	ID       string
	Accepted bool
}

func (e *AlreadyDecidedError) Error() string {
	verb := "rejected"
	if e.Accepted {
		verb = "accepted"
	}
	return fmt.Sprintf("proposal %q was already %s", e.ID, verb)
}

// NoProposalError names a proposal that is not in the current list:
// withdrawn, never sent to this node, or mistyped.
type NoProposalError struct{ ID string }

func (e *NoProposalError) Error() string { return fmt.Sprintf("there is no proposal %q", e.ID) }

// Store is what the admin UI calls about the cloud's proposals: List
// for what to show, Accept and Reject for the two buttons the owner
// has.
//
// It keeps nothing in memory between calls. Two processes read this
// directory — the admin UI and the core's feedback loop — and a cache
// here would go stale the moment the other one writes.
type Store struct {
	dir string
	mu  sync.Mutex
}

// Open points a Store at the shared directory rules.json, proposals.json
// and proposal-decisions.json all live in.
func Open(dir string) *Store { return &Store{dir: dir} }

// List returns what the owner should be asked about right now:
// proposals that are neither expired nor already decided, and advice
// about a rule that still exists in current — the same rules.Set the
// caller is about to show on the rules page, so the two never disagree
// about which rules there are.
func (s *Store) List(now time.Time, current *rules.Set) (proposals []Proposal, advice []Advice, err error) {
	return nil, nil, fmt.Errorf("not implemented")
}

// Accept writes the proposed rule into rules.json in shadow, exactly as
// the cloud sent it — the wire format has nowhere to put a mode, and
// shadow is the only one a proposal ever gets — and records that the
// owner accepted it, so it is not offered again.
func (s *Store) Accept(id string, rulesStore *rules.Store, who string, now time.Time) error {
	return fmt.Errorf("not implemented")
}

// Reject records that the owner declined a proposal. reason is his own
// words — signed in the admin UI so it is clear the cloud reads it —
// and capped at 500 runes, the same limit the node's answer carries: a
// longer one is refused here, not truncated on the way out where he
// cannot see it happen.
func (s *Store) Reject(id, reason, who string, now time.Time) error {
	if n := utf8.RuneCountInString(reason); n > maxReasonRunes {
		return fmt.Errorf("reason is %d runes, the limit is %d", n, maxReasonRunes)
	}
	return fmt.Errorf("not implemented")
}

func decisionByID(f decisionsFile, id string) (Decision, bool) {
	for _, d := range f.Decisions {
		if d.ID == id {
			return d, true
		}
	}
	return Decision{}, false
}

// Decisions returns every decision recorded so far, oldest first — for
// the core's feedback loop.
func (s *Store) Decisions() ([]Decision, error) {
	f, err := s.readDecisions()
	if err != nil {
		return nil, err
	}
	out := make([]Decision, len(f.Decisions))
	copy(out, f.Decisions)
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// Advice returns the cloud's current advice list, unfiltered — for the
// core's feedback loop, which works out "done" for itself against
// rules.json and needs to see advice whose rule has already vanished.
func (s *Store) Advice() ([]Advice, error) {
	doc, err := s.readDocument()
	if err != nil {
		return nil, err
	}
	return doc.Advice, nil
}

func (s *Store) readDocument() (Document, error) {
	var doc Document
	raw, err := os.ReadFile(filepath.Join(s.dir, FileName))
	if errors.Is(err, fs.ErrNotExist) {
		return doc, nil
	}
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("%s: %w", FileName, err)
	}
	return doc, nil
}

func (s *Store) readDecisions() (decisionsFile, error) {
	var f decisionsFile
	raw, err := os.ReadFile(filepath.Join(s.dir, DecisionsFileName))
	if errors.Is(err, fs.ErrNotExist) {
		f.Format = decisionsFormat
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		return f, fmt.Errorf("%s: %w", DecisionsFileName, err)
	}
	return f, nil
}

func (s *Store) writeDecisions(f decisionsFile) error {
	f.Format = decisionsFormat
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return writeAtomic(filepath.Join(s.dir, DecisionsFileName), raw, 0o640)
}
