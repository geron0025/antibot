package rules

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

// Limiter counts frequency. The time is passed in explicitly rather than
// taken inside: a replay over history must arrive at the same decisions
// as the hot path, and an event carries a time of its own.
type Limiter interface {
	Exceeded(key string, limit int, window time.Duration, when time.Time) bool
}

// Set holds the compiled rules in the order they are applied.
type Set struct {
	rules   []*compiled
	all     []Rule
	limiter Limiter
}

// Build validates and orders the rules.
//
// An error in even one rule discards the whole set: a half-applied set is
// not what the human wrote, and it is worst of all in that it looks like
// it works. The errors are collected all at once rather than one per
// start.
func Build(list []Rule, limiter Limiter) (*Set, error) {
	var errs []error
	seen := make(map[string]struct{}, len(list))
	ready := make([]*compiled, 0, len(list))

	for i := range list {
		r := list[i]
		if _, ok := seen[r.ID]; ok && r.ID != "" {
			errs = append(errs, fmt.Errorf("rule %q occurs twice", r.ID))
			continue
		}
		seen[r.ID] = struct{}{}

		c, err := r.Compile()
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !r.enabled() {
			continue
		}
		ready = append(ready, c)
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	// Higher priority comes first. At equal priorities the order is set
	// by the id rather than by the order of lines in the file: swapping
	// two rules around must not change the decisions, otherwise the
	// replay over history and the hot path diverge for no reason at all.
	sort.SliceStable(ready, func(i, j int) bool {
		a, b := ready[i].rule, ready[j].rule
		if a.Priority != b.Priority {
			return a.Priority > b.Priority
		}
		return a.ID < b.ID
	})

	return &Set{rules: ready, all: list, limiter: limiter}, nil
}

// All returns every rule, disabled ones included, in the order they lie
// in the file. Needed for `rules list`.
func (s *Set) All() []Rule { return s.all }

// Effective returns the rules in the order they are applied, without the
// disabled ones.
func (s *Set) Effective() []Rule {
	out := make([]Rule, 0, len(s.rules))
	for _, c := range s.rules {
		out = append(out, c.rule)
	}
	return out
}

// Decide applies the set to the signals of a request.
//
// The first rule that fires in active mode wins; rules in shadow mode are
// only noted in the signals and do not stop the walk. That is why an
// exception is made not by a negation inside every prohibition but by an
// allowing rule higher in priority.
func (s *Set) Decide(r *facts.Request) proxy.Decision {
	for _, c := range s.rules {
		if !c.inScope(r.Host) || !c.matches(r) {
			continue
		}
		if c.rule.Mode == Shadow {
			r.Shadow = append(r.Shadow, c.rule.ID)
			continue
		}
		return s.decision(c, r)
	}
	return proxy.Pass()
}

func (s *Set) decision(c *compiled, r *facts.Request) proxy.Decision {
	rule := c.rule
	switch rule.Action.Type {
	case Allow:
		return proxy.Decision{Action: proxy.ActionAllow, Rule: rule.ID}

	case Block:
		return proxy.Decision{
			Action: proxy.ActionBlock,
			Rule:   rule.ID,
			Status: rule.Action.Status,
			Body:   rule.Action.Body,
		}

	case Ratelimit:
		// Without a counter there is nothing to limit with. Letting the
		// request through and saying so in the event is more honest than
		// blocking by a count that does not exist.
		if s.limiter == nil {
			return proxy.Decision{Action: proxy.ActionPass, Rule: rule.ID}
		}
		read, _ := fieldForKey(rule.limiterKey())
		key := rule.ID + "\x00" + read(r)
		if s.limiter.Exceeded(key, rule.Action.Limit, c.window, r.Time) {
			return proxy.Decision{
				Action: proxy.ActionRatelimit,
				Rule:   rule.ID,
				Status: rule.Action.Status,
				Body:   rule.Action.Body,
			}
		}
		// The rule fired and the decision is made — the walk goes no
		// further. A prohibition of lower priority over the same clients
		// will not apply in this case; that cost a post-mortem in the
		// previous project, hence it is said out loud.
		return proxy.Decision{Action: proxy.ActionPass, Rule: rule.ID}
	}
	return proxy.Pass()
}

// fieldForKey gives a reader of the field the frequency is counted by.
// Only string fields will do: counting frequency by a bool means two
// buckets for all the traffic.
func fieldForKey(field string) (func(*facts.Request) string, bool) {
	kind, ok := facts.FieldKind(field)
	if !ok || (kind != facts.KindString && kind != facts.KindAddr) {
		return nil, false
	}
	return func(r *facts.Request) string {
		v, _ := r.Value(field)
		s, _ := v.(string)
		return s
	}, true
}
