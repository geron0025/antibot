package rules

import (
	"fmt"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/hostnorm"
)

// Rule modes.
const (
	// Shadow means the match is written into the event and the request
	// goes on. A watching rule is only useful if someone reads it, so the
	// shadows that fired land in the event in a separate field.
	Shadow = "shadow"

	// Active means the rule renders a decision and the walk stops on it.
	Active = "active"
)

// Actions.
const (
	Block     = "block"
	Ratelimit = "ratelimit"

	// Allow is required as an action of its own. Without it an exception
	// has to be written inside every blocking rule, and an exception
	// forgotten in one rule out of ten shows nothing of itself — until
	// the post-mortem.
	Allow = "allow"
)

// MaxLimit is the largest sensible rate limit for a single node.
const MaxLimit = 1 << 20

// Rule is one rule in the form it lies in rules.json.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`

	// Scope is where the rule applies: ["*"] or a list of domains. The
	// form "*.example.ru" is allowed — the domain itself and all its
	// subdomains.
	//
	// The scope exists from day one and is mandatory: a node serves more
	// than one site, and a rule written for one site is usually harmful
	// on the rest.
	Scope []string `json:"scope"`

	// An absent Enabled means enabled. That is safe exactly because mode
	// is mandatory: a rule cannot end up active by an oversight.
	Enabled *bool `json:"enabled,omitempty"`

	Mode      string    `json:"mode"`
	Priority  int       `json:"priority"`
	Condition Condition `json:"condition"`
	Action    Action    `json:"action"`
}

// Action is what the rule does with a matched request.
type Action struct {
	Type string `json:"type"`

	// For block: what to answer with. Zero means 403.
	Status int    `json:"status,omitempty"`
	Body   string `json:"body,omitempty"`

	// For ratelimit: how many requests over what window and by which
	// field to count. The default field is ip.
	Limit  int    `json:"limit,omitempty"`
	Window string `json:"window,omitempty"`
	Key    string `json:"key,omitempty"`
}

func (r *Rule) enabled() bool { return r.Enabled == nil || *r.Enabled }

// compiled is a rule ready to be applied. The condition is already
// checked and turned into a function, the scope into a predicate over the
// domain, and the limiter window into a duration.
type compiled struct {
	rule    Rule
	matches Matcher
	inScope func(host string) bool
	window  time.Duration
}

// Compile validates the rule as a whole. Everything that can be caught
// before the rule reaches the hot path is caught here.
func (r *Rule) Compile() (*compiled, error) {
	name := r.ID
	if name == "" {
		return nil, fmt.Errorf("a rule without an id")
	}
	if strings.ContainsAny(name, " \t\n") {
		return nil, fmt.Errorf("rule %q: whitespace in the id; the id goes into events and reports", name)
	}

	switch r.Mode {
	case Shadow, Active:
	case "":
		return nil, fmt.Errorf("rule %q: no mode set (%s or %s)", name, Shadow, Active)
	default:
		return nil, fmt.Errorf("rule %q: unknown mode %q", name, r.Mode)
	}

	inScope, err := compileScope(name, r.Scope)
	if err != nil {
		return nil, err
	}

	matches, err := r.Condition.Compile()
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", name, err)
	}

	c := &compiled{rule: *r, matches: matches, inScope: inScope}

	switch r.Action.Type {
	case Allow:
	case Block:
		st := r.Action.Status
		if st != 0 && (st < 100 || st > 599) {
			return nil, fmt.Errorf("rule %q: status %d is not a response code", name, st)
		}
	case Ratelimit:
		if r.Action.Limit <= 0 {
			return nil, fmt.Errorf("rule %q: ratelimit without limit", name)
		}
		// The ceiling guards against a typo of one extra zero: the limit
		// is kept as timestamps in memory, and "a billion requests per
		// minute" means not a lenient rule but eaten memory.
		if r.Action.Limit > MaxLimit {
			return nil, fmt.Errorf("rule %q: limit %d is above the ceiling of %d",
				name, r.Action.Limit, MaxLimit)
		}
		if r.Action.Window == "" {
			return nil, fmt.Errorf("rule %q: ratelimit without window (\"1m\", for example)", name)
		}
		window, err := time.ParseDuration(r.Action.Window)
		if err != nil || window <= 0 {
			return nil, fmt.Errorf("rule %q: window %q is not a duration like 1m", name, r.Action.Window)
		}
		c.window = window
		if key := r.limiterKey(); key != "ip" {
			if _, ok := fieldForKey(key); !ok {
				return nil, fmt.Errorf("rule %q: key %q — there is no such field", name, key)
			}
		}
	case "":
		return nil, fmt.Errorf("rule %q: no action.type set", name)
	default:
		return nil, fmt.Errorf("rule %q: unknown action %q; allowed: %s, %s, %s",
			name, r.Action.Type, Block, Allow, Ratelimit)
	}

	return c, nil
}

func (r *Rule) limiterKey() string {
	if r.Action.Key == "" {
		return "ip"
	}
	return r.Action.Key
}

// compileScope turns a list of domains into a predicate.
func compileScope(name string, list []string) (func(string) bool, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("rule %q: no scope set; for all domains write [\"*\"]", name)
	}

	everywhere := false
	exact := make(map[string]struct{}, len(list))
	var suffixes []string

	for _, s := range list {
		switch {
		case s == "*":
			everywhere = true
		case strings.HasPrefix(s, "*."):
			// Only the part after the asterisk is normalized: converting
			// the whole thing to punycode sees an empty label and appends
			// the dot twice.
			tail := hostnorm.Normalize(strings.TrimPrefix(s, "*."))
			if tail == "" {
				return nil, fmt.Errorf("rule %q: an empty domain in scope", name)
			}
			exact[tail] = struct{}{}
			suffixes = append(suffixes, "."+tail)
		case s == "":
			return nil, fmt.Errorf("rule %q: an empty domain in scope", name)
		default:
			exact[hostnorm.Normalize(s)] = struct{}{}
		}
	}

	if everywhere {
		return func(string) bool { return true }, nil
	}
	return func(host string) bool {
		if _, ok := exact[host]; ok {
			return true
		}
		for _, s := range suffixes {
			if strings.HasSuffix(host, s) {
				return true
			}
		}
		return false
	}, nil
}
