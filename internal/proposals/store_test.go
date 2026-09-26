package proposals

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/rules"
)

func newRulesStore(t *testing.T, dir string) *rules.Store {
	t.Helper()
	st, err := rules.Open(filepath.Join(dir, "rules.json"), rules.NewWindows(), quietLog())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func writeProposalsDoc(t *testing.T, dir string, doc Document) {
	t.Helper()
	if doc.Format == 0 {
		doc.Format = FormatVersion
	}
	if err := writeAtomic(filepath.Join(dir, FileName), marshal(t, doc), 0o640); err != nil {
		t.Fatal(err)
	}
}

func sampleProposal(id string) Proposal {
	return Proposal{
		ID:        id,
		CreatedAt: time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		Rule: ProposedRule{
			ID: id, Scope: []string{"shop.example.ru"}, Priority: 100,
			Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
			Action:    rules.Action{Type: rules.Block, Status: 403},
		},
		Why:      "a test proposal",
		Evidence: Evidence{Window: "w", Requests: 1, Share: 0.1, WouldBlock: 1},
	}
}

func emptySet(t *testing.T) *rules.Set {
	t.Helper()
	set, err := rules.Build(nil, rules.NewWindows())
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// List hides what the owner should not be asked about again: expired
// proposals, and proposals already decided one way or the other.
// Accept writes the rule into rules.json in shadow, exactly as
// proposed, and a decision cannot be made twice.
func TestStoreListAcceptReject(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)

	live := sampleProposal("cloud-live")
	expired := sampleProposal("cloud-expired")
	expired.ExpiresAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	toReject := sampleProposal("cloud-to-reject")
	toAccept := sampleProposal("cloud-to-accept")

	writeProposalsDoc(t, dir, Document{
		Node: testNodeID, CreatedAt: time.Now(),
		Proposals: []Proposal{live, expired, toReject, toAccept},
	})

	s := Open(dir)
	now := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)

	got, _, err := s.List(now, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 live proposals (expired hidden), got %d", len(got))
	}

	if err := s.Reject("cloud-to-reject", "not for us", "owner", now); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if err := s.Accept("cloud-to-accept", rulesStore, "owner", now); err != nil {
		t.Fatalf("accept: %v", err)
	}

	got, _, err = s.List(now, emptySet(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "cloud-live" {
		t.Fatalf("expected only cloud-live left to decide, got %d proposals", len(got))
	}

	all := rulesStore.Set().All()
	if len(all) != 1 {
		t.Fatalf("expected exactly one rule written, got %d", len(all))
	}
	if all[0].ID != "cloud-to-accept" || all[0].Mode != rules.Shadow || all[0].Enabled != nil {
		t.Fatalf("the accepted rule was not written as proposed: %+v", all[0])
	}

	// A proposal already decided cannot be decided again — either way.
	var already *AlreadyDecidedError
	if err := s.Reject("cloud-to-reject", "again", "owner", now); !errors.As(err, &already) {
		t.Fatalf("a rejected proposal was decided again: %v", err)
	}
	if err := s.Accept("cloud-to-accept", rulesStore, "owner", now); !errors.As(err, &already) {
		t.Fatalf("an accepted proposal was decided again: %v", err)
	}
}

// The reason is the one piece of the owner's own text that reaches the
// cloud, and the node's answer caps it at 500 runes — refused here,
// rather than silently cut on the way out where he cannot see it.
func TestRejectReasonTooLong(t *testing.T) {
	dir := t.TempDir()
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Proposals: []Proposal{sampleProposal("cloud-x")}})

	s := Open(dir)
	if err := s.Reject("cloud-x", strings.Repeat("a", 501), "owner", time.Now()); err == nil {
		t.Fatal("a 501-rune reason was accepted")
	}
	if err := s.Reject("cloud-x", strings.Repeat("a", 500), "owner", time.Now()); err != nil {
		t.Fatalf("a 500-rune reason was refused: %v", err)
	}
}

// Accepting a proposal whose rule id the owner already has is a clear
// error, not a silently merged rule.
func TestAcceptRefusesADuplicateRuleID(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)

	dup := sampleProposal("cloud-dup")
	if err := rulesStore.Add(dup.asRule()); err != nil {
		t.Fatal(err)
	}
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Proposals: []Proposal{dup}})

	s := Open(dir)
	var exists *rules.RuleExistsError
	if err := s.Accept("cloud-dup", rulesStore, "owner", time.Now()); !errors.As(err, &exists) {
		t.Fatalf("expected a RuleExistsError, got %v", err)
	}
}

// Advice is shown only while the rule it is about still exists, under
// the hash the owner's rule set actually has right now.
func TestListShowsAdviceOnlyWhenTheRuleExists(t *testing.T) {
	r := rules.Rule{
		ID: "owner-rule", Scope: []string{"*"}, Mode: rules.Shadow, Priority: 1,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block},
	}
	set, err := rules.Build([]rules.Rule{r}, rules.NewWindows())
	if err != nil {
		t.Fatal(err)
	}

	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	present := Advice{ID: "cloud-advice-present", ExpiresAt: future, Rule: r.Hash(),
		Suggest: SuggestDisable, Why: "x", Evidence: AdviceEvidence{Window: "w"}}
	gone := Advice{ID: "cloud-advice-gone", ExpiresAt: future, Rule: "0000000000000000",
		Suggest: SuggestDisable, Why: "x", Evidence: AdviceEvidence{Window: "w"}}

	dir := t.TempDir()
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Advice: []Advice{present, gone}})

	s := Open(dir)
	_, advice, err := s.List(time.Now(), set)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 1 || advice[0].ID != "cloud-advice-present" {
		t.Fatalf("expected only the advice about a rule that still exists, got %d entries", len(advice))
	}
}
