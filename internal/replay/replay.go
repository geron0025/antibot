// Package replay runs the rules over events that were already recorded.
//
// This is the check of a rule against history — and the only one: there
// is a single rule engine in the project, the very same internal/rules. A
// second one, "for checking", would drift apart from the first, and a
// human would turn rules on by the wrong numbers with no way of finding
// out.
package replay

import (
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
	"github.com/geron0025/antibot/internal/rules"
)

// Options of a run.
type Options struct {
	// Dir holds the log files. Either it or Files.
	Dir   string
	Files []string

	// From and To cut events off by time. Zero means no bound.
	From, To time.Time

	// Samples is how many events per rule to keep so that a human can
	// look at them one by one. Going through them by hand is a mandatory
	// step: numbers show the size of a group but not who is in it.
	Samples int
}

// RuleStats are the statistics of a single rule.
type RuleStats struct {
	ID      string
	Mode    string
	Action  string
	Matched int
	IPs     int
	Hosts   int
	UAs     int
	Samples []facts.Request

	ips   map[string]struct{}
	hosts map[string]struct{}
	uas   map[string]struct{}
}

// Result of a run.
type Result struct {
	Events int
	Read   int
	Broken int

	From, To time.Time

	// Decisions is how many requests received each decision.
	Decisions map[string]int

	// Divergences is how many requests would have received a decision
	// different from the one recorded in the event. That is what a run is
	// made for: "how many live people will the new rule cut off" is
	// answered only this way.
	Divergences map[string]int

	Rules map[string]*RuleStats

	// IPs is the number of unique addresses over the whole run, for the
	// coverage share.
	IPs int
	ips map[string]struct{}
}

// Run applies the set to every event.
//
// The events are fed to the matcher in the same order they happened: the
// rate limiter counts by the event's time, and a shuffled order would
// give numbers that never occurred in production.
func Run(o Options, set *rules.Set) (*Result, error) {
	result := &Result{
		Decisions:   map[string]int{},
		Divergences: map[string]int{},
		Rules:       map[string]*RuleStats{},
		ips:         map[string]struct{}{},
	}

	read, err := events.Read(events.Filter{
		Dir: o.Dir, Files: o.Files, From: o.From, To: o.To,
	}, func(r facts.Request) error {
		result.event(r, o, set)
		return nil
	})
	if err != nil {
		return nil, err
	}
	result.Read, result.Broken = read.Read, read.Broken

	result.IPs = len(result.ips)
	for _, s := range result.Rules {
		s.IPs, s.Hosts, s.UAs = len(s.ips), len(s.hosts), len(s.uas)
	}
	return result, nil
}

func (result *Result) event(r facts.Request, o Options, set *rules.Set) {
	result.Events++
	if result.From.IsZero() || r.Time.Before(result.From) {
		result.From = r.Time
	}
	if r.Time.After(result.To) {
		result.To = r.Time
	}
	if r.IP != "" {
		result.ips[r.IP] = struct{}{}
	}

	was := r.Decision

	// The recorded decision is erased before the run: otherwise the set
	// would be counted on top of the past decision, while the question to
	// answer is "what would have happened had this set been in force
	// then".
	r.Decision, r.Rule, r.Shadow = "", "", nil

	decision := set.Decide(&r)
	result.Decisions[decision.Action]++

	if was != "" && was != decision.Action {
		result.Divergences[was+"→"+decision.Action]++
	}

	// The rule that fired and every shadow land in the statistics: a
	// watcher is set up precisely to be looked at before it is turned on.
	if decision.Rule != "" {
		result.forRule(decision.Rule, rules.Active, decision.Action, r, o)
	}
	for _, id := range r.Shadow {
		result.forRule(id, rules.Shadow, "", r, o)
	}
}

func (result *Result) forRule(id, mode, action string, r facts.Request, o Options) {
	s, ok := result.Rules[id]
	if !ok {
		s = &RuleStats{
			ID: id, Mode: mode, Action: action,
			ips:   map[string]struct{}{},
			hosts: map[string]struct{}{},
			uas:   map[string]struct{}{},
		}
		result.Rules[id] = s
	}
	s.Matched++
	if r.IP != "" {
		s.ips[r.IP] = struct{}{}
	}
	if r.Host != "" {
		s.hosts[r.Host] = struct{}{}
	}
	if r.UA != "" {
		s.uas[r.UA] = struct{}{}
	}
	if len(s.Samples) < o.Samples {
		s.Samples = append(s.Samples, r)
	}
}

// Share is the fraction of requests a rule touched. The number an
// analysis starts from: a rule that touches a noticeable share of the
// traffic almost certainly touches people too.
func (result *Result) Share(id string) float64 {
	s, ok := result.Rules[id]
	if !ok || result.Events == 0 {
		return 0
	}
	return float64(s.Matched) / float64(result.Events)
}

// Blocked is how many requests the set would not have let through.
func (result *Result) Blocked() int {
	return result.Decisions[proxy.ActionBlock] + result.Decisions[proxy.ActionRatelimit]
}
