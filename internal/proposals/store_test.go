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

// The node's answer shows advice rejected with a reason
// ("cloud-advice-cuts-people-2026-09" … "это наши партнёры, так и
// задумано" in docs/*/protocol/proposals.md «Ответ ноды»), so Reject
// must work on an advice id exactly as it does on a proposal's: reason
// capped at 500 runes, recorded in the decisions.
func TestRejectWorksForAdvice(t *testing.T) {
	r := rules.Rule{
		ID: "owner-rule", Scope: []string{"*"}, Mode: rules.Shadow, Priority: 1,
		Condition: rules.Condition{Field: "network.class", Op: "eq", Value: json.RawMessage(`"hosting"`)},
		Action:    rules.Action{Type: rules.Block},
	}
	future := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	adv := Advice{ID: "cloud-advice-cuts-people-2026-09", ExpiresAt: future, Rule: r.Hash(),
		Suggest: SuggestDisable, Why: "x", Evidence: AdviceEvidence{Window: "w"}}

	dir := t.TempDir()
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Advice: []Advice{adv}})

	s := Open(dir)
	now := time.Date(2026, 9, 10, 9, 5, 0, 0, time.UTC)
	if err := s.Reject(adv.ID, "это наши партнёры, так и задумано", "owner", now); err != nil {
		t.Fatalf("reject: %v", err)
	}

	decisions, err := s.Decisions()
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 1 {
		t.Fatalf("expected one decision, got %d", len(decisions))
	}
	d := decisions[0]
	if d.ID != adv.ID || d.Accepted || d.At != now || d.Reason != "это наши партнёры, так и задумано" {
		t.Fatalf("the decision was not recorded correctly: %+v", d)
	}

	// A reason over 500 runes is refused, the same as for a proposal.
	if err := s.Reject(adv.ID, strings.Repeat("a", 501), "owner", now); err == nil {
		t.Fatal("a 501-rune reason on advice was accepted")
	}

	// Already decided: cannot be decided again.
	var already *AlreadyDecidedError
	if err := s.Reject(adv.ID, "again", "owner", now); !errors.As(err, &already) {
		t.Fatalf("a rejected advice was decided again: %v", err)
	}
}

// Once rejected, an advice is hidden by List — and stays hidden even if
// the cloud, not knowing better, sends the very same id again:
// docs/*/protocol/proposals.md «Отказ» says the cloud stops sending it,
// but also "если оно всё же приехало, нода его не показывает".
func TestListHidesRejectedAdviceEvenWhenResent(t *testing.T) {
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
	adv := Advice{ID: "cloud-advice-x", ExpiresAt: future, Rule: r.Hash(),
		Suggest: SuggestDisable, Why: "x", Evidence: AdviceEvidence{Window: "w"}}

	dir := t.TempDir()
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Advice: []Advice{adv}})
	s := Open(dir)

	_, advice, err := s.List(time.Now(), set)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 1 {
		t.Fatalf("expected the advice to show before any decision, got %d", len(advice))
	}

	if err := s.Reject(adv.ID, "not for us", "owner", time.Now()); err != nil {
		t.Fatalf("reject: %v", err)
	}

	_, advice, err = s.List(time.Now(), set)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 0 {
		t.Fatalf("a rejected advice was shown: %d entries", len(advice))
	}

	// The cloud re-sends the same id, still believing it should show.
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Advice: []Advice{adv}})
	_, advice, err = s.List(time.Now(), set)
	if err != nil {
		t.Fatal(err)
	}
	if len(advice) != 0 {
		t.Fatalf("a rejected advice reappeared after being resent: %d entries", len(advice))
	}
}

// Advice is acted on with the rule's own buttons, not added by one:
// Accept on an advice id is a clear error, not a confusing "no such
// proposal".
func TestAcceptRefusesAdvice(t *testing.T) {
	dir := t.TempDir()
	rulesStore := newRulesStore(t, dir)

	adv := Advice{ID: "cloud-advice-x", ExpiresAt: time.Now().Add(time.Hour), Rule: "0123456789abcdef",
		Suggest: SuggestReview, Why: "x", Evidence: AdviceEvidence{Window: "w"}}
	writeProposalsDoc(t, dir, Document{Node: testNodeID, Advice: []Advice{adv}})

	s := Open(dir)
	var wrongKind *AdviceCannotBeAcceptedError
	if err := s.Accept(adv.ID, rulesStore, "owner", time.Now()); !errors.As(err, &wrongKind) {
		t.Fatalf("expected AdviceCannotBeAcceptedError, got %v", err)
	}
}
