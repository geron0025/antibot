// Package proposals is the node's side of the third channel between the
// two parts: docs/*/protocol/proposals.md. Facts flow down from the
// cloud automatically; the aggregate flows up automatically; this one
// carries a draft rule down and a human's decision up, and nothing here
// ever crosses that line by itself.
//
// Three pieces, one for each verb in Д8 of the cloud's spec:
//
//   - Fetcher downloads the cloud's list, checks it — signature, node,
//     schema, the cloud- prefix, the scope, that the rule compiles — and,
//     only if every check passes, writes it whole to proposals.json next
//     to rules.json. Any failed check leaves the previous list in force.
//   - Store is what the admin UI calls when the owner presses a button:
//     List for what to show, Accept and Reject for what happens next.
//     Accepting writes the rule into rules.json in shadow, exactly as
//     the cloud proposed it — the mode is not in the wire format, and
//     the node has nowhere else to take it from.
//   - Feedback reports upward what became of each proposal and advice:
//     accepted, then active or disabled or removed as the owner acts on
//     the rule with the ordinary buttons he already has; a rejection,
//     with the reason he wrote if he wrote one; an advice, done.
//
// A proposal the owner has not decided is a draft and nothing else: it
// cannot block a single request until Accept has written it down.
package proposals

import (
	"time"

	"github.com/geron0025/antibot/internal/rules"
)

// FormatVersion is the version of the proposals document and of the
// feedback this node sends back, as docs/*/protocol/proposals.md fixes
// it. The two travel together because they describe one channel.
const FormatVersion = 1

// Advice suggestions. Only these three: the cloud does not get to word
// its own button.
const (
	SuggestDisable = "disable"
	SuggestShadow  = "shadow"
	SuggestReview  = "review"
)

// Feedback states, as the protocol names them in the node's answer.
const (
	StateAccepted = "accepted"
	StateActive   = "active"
	StateDisabled = "disabled"
	StateRemoved  = "removed"
	StateRejected = "rejected"
	StateDone     = "done"
)

// Document is the whole of what the cloud sends for one node.
//
// A list arrives whole every time: a proposal missing from it is a
// proposal the cloud withdrew, and the node hides it — nothing here is
// merged with what came before.
type Document struct {
	Format    int        `json:"format"`
	Node      string     `json:"node"`
	CreatedAt time.Time  `json:"created_at"`
	Proposals []Proposal `json:"proposals"`
	Advice    []Advice   `json:"advice,omitempty"`
}

// Proposal is a draft rule the owner may add with one button.
type Proposal struct {
	ID                   string       `json:"id"`
	CreatedAt            time.Time    `json:"created_at"`
	ExpiresAt            time.Time    `json:"expires_at"`
	RequiresFactsVersion int          `json:"requires_facts_version,omitempty"`
	Rule                 ProposedRule `json:"rule"`
	Why                  string       `json:"why"`
	Evidence             Evidence     `json:"evidence"`
}

// ProposedRule is the rule as the wire carries it: everything rules.Rule
// has except mode and enabled — the protocol has nowhere to put them,
// on purpose. Accepting a proposal is what supplies the mode, and it is
// always shadow.
type ProposedRule struct {
	ID        string          `json:"id"`
	Name      string          `json:"name,omitempty"`
	Scope     []string        `json:"scope"`
	Priority  int             `json:"priority"`
	Condition rules.Condition `json:"condition"`
	Action    rules.Action    `json:"action"`
}

// Evidence is the numbers behind a proposal — the owner's own traffic,
// so that antibot replay can be asked to show the same ones.
type Evidence struct {
	Window              string  `json:"window"`
	Requests            int     `json:"requests"`
	Share               float64 `json:"share"`
	Networks            int     `json:"networks,omitempty"`
	Addresses           int     `json:"addresses,omitempty"`
	WouldBlock          int     `json:"would_block"`
	WouldBlockProtected int     `json:"would_block_protected"`
}

// Advice is a note about a rule that already exists, named by its hash
// because the cloud never learns the owner's ids. It adds nothing and
// changes nothing; the owner acts on it with the buttons the rule
// already has.
type Advice struct {
	ID        string         `json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	ExpiresAt time.Time      `json:"expires_at"`
	Rule      string         `json:"rule"` // rules.Rule.Hash of the rule this is about
	Suggest   string         `json:"suggest"`
	Why       string         `json:"why"`
	Evidence  AdviceEvidence `json:"evidence"`
}

// AdviceEvidence is the numbers behind an advice: fewer than a
// proposal's, because there is no networks/addresses count kept per
// rule.
type AdviceEvidence struct {
	Window     string  `json:"window"`
	Requests   int     `json:"requests"`
	Share      float64 `json:"share"`
	WithCookie int     `json:"with_cookie,omitempty"`
	Protected  int     `json:"protected,omitempty"`
}

// Item is one line of the node's answer: what became of one proposal or
// advice.
type Item struct {
	ID     string    `json:"id"`
	State  string    `json:"state"`
	At     time.Time `json:"at"`
	Rule   string    `json:"rule,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

// Feedback is the body the node posts to <cloud.url without
// /ingest>/proposals/feedback.
type Feedback struct {
	Format int    `json:"format"`
	Node   string `json:"node"`
	SentAt string `json:"sent_at"`
	Items  []Item `json:"items"`
}

// maxItemsPerPost mirrors the schema's cap on the feedback body: sending
// more would be refused whole, and the rest waits for the next cycle.
const maxItemsPerPost = 200

// asRule turns a proposed rule into the shape rules.Store.Add takes: the
// mode is always shadow, because the protocol never carries any other
// value, and enabled is left nil — the same "on unless said otherwise"
// a rule written by hand starts with.
func (p *Proposal) asRule() rules.Rule {
	return rules.Rule{
		ID:        p.Rule.ID,
		Name:      p.Rule.Name,
		Scope:     p.Rule.Scope,
		Mode:      rules.Shadow,
		Priority:  p.Rule.Priority,
		Condition: p.Rule.Condition,
		Action:    p.Rule.Action,
	}
}
