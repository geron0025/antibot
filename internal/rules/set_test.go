package rules

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

func parseRule(t *testing.T, s string) Rule {
	t.Helper()
	var r Rule
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatalf("parsing the rule: %v", err)
	}
	return r
}

func buildSet(t *testing.T, limiter Limiter, rules ...string) *Set {
	t.Helper()
	list := make([]Rule, 0, len(rules))
	for _, s := range rules {
		list = append(list, parseRule(t, s))
	}
	set, err := Build(list, limiter)
	if err != nil {
		t.Fatalf("building the set: %v", err)
	}
	return set
}

const (
	blockHosting = `{"id":"block-hosting","scope":["*"],"mode":"active","priority":100,
		"condition":{"field":"network.class","op":"eq","value":"hosting"},
		"action":{"type":"block","status":403}}`

	allowOwn = `{"id":"allow-monitoring","scope":["*"],"mode":"active","priority":200,
		"condition":{"field":"ip","op":"cidr","value":["203.0.113.0/24"]},
		"action":{"type":"allow"}}`

	watchScraper = `{"id":"watch-scraper","scope":["*"],"mode":"shadow","priority":300,
		"condition":{"field":"ua","op":"contains","value":"curl"},
		"action":{"type":"block"}}`
)

// An allowing rule higher in priority overrides a prohibition. That is
// how exceptions are made: a negation inside every prohibition will not
// do — an exception forgotten in one rule out of ten shows nothing of
// itself.
func TestAllowHigherInPriorityWins(t *testing.T) {
	set := buildSet(t, nil, blockHosting, allowOwn)

	r := facts.Request{Host: "example.ru", IP: "203.0.113.7", NetClass: "hosting"}
	if d := set.Decide(&r); d.Action != proxy.ActionAllow || d.Rule != "allow-monitoring" {
		t.Errorf("own network on hosting: got %+v", d)
	}

	foreign := facts.Request{Host: "example.ru", IP: "198.51.100.9", NetClass: "hosting"}
	if d := set.Decide(&foreign); d.Action != proxy.ActionBlock || d.Rule != "block-hosting" {
		t.Errorf("a stranger on hosting: got %+v", d)
	}
}

// A rule in shadow mode is noted in the signals and does not stop the
// walk: watching is useful only when it is visible in the event.
func TestShadowDoesNotChangeTheDecisionButLeavesATrace(t *testing.T) {
	set := buildSet(t, nil, watchScraper, blockHosting)

	r := facts.Request{Host: "example.ru", UA: "curl/8.4", NetClass: "hosting"}
	d := set.Decide(&r)

	if d.Action != proxy.ActionBlock || d.Rule != "block-hosting" {
		t.Errorf("the decision must come from the active rule, got %+v", d)
	}
	if len(r.Shadow) != 1 || r.Shadow[0] != "watch-scraper" {
		t.Errorf("the shadow was not recorded: %v", r.Shadow)
	}

	// Only the watcher matched — the request goes on, but the trace stays.
	shadowOnly := facts.Request{Host: "example.ru", UA: "curl/8.4"}
	if d := set.Decide(&shadowOnly); d.Action != proxy.ActionPass {
		t.Errorf("a watcher must not block: %+v", d)
	}
	if len(shadowOnly.Shadow) != 1 {
		t.Errorf("the shadow was not recorded: %v", shadowOnly.Shadow)
	}
}

func TestRuleScope(t *testing.T) {
	set := buildSet(t, nil,
		`{"id":"one-site","scope":["shop.example.ru"],"mode":"active","priority":10,
		  "condition":{"field":"method","op":"eq","value":"GET"},
		  "action":{"type":"block"}}`,
		`{"id":"subdomains","scope":["*.example.com"],"mode":"active","priority":5,
		  "condition":{"field":"method","op":"eq","value":"GET"},
		  "action":{"type":"block"}}`)

	checks := map[string]string{
		"shop.example.ru":     "one-site",
		"other.example.ru":    "",
		"example.com":         "subdomains",
		"a.b.example.com":     "subdomains",
		"notexample.com":      "",
		"example.com.evil.ru": "",
	}
	for host, want := range checks {
		r := facts.Request{Host: host, Method: "GET"}
		d := set.Decide(&r)
		if d.Rule != want {
			t.Errorf("host %s: %q fired, want %q", host, d.Rule, want)
		}
	}
}

// The order of rules in the file must not affect the decision: otherwise
// the replay over history and the hot path diverge after a harmless
// reshuffling of lines.
func TestOrderInTheFileDoesNotMatter(t *testing.T) {
	forward := buildSet(t, nil, blockHosting, allowOwn, watchScraper)
	backward := buildSet(t, nil, watchScraper, allowOwn, blockHosting)

	a := facts.Request{Host: "example.ru", IP: "203.0.113.7", NetClass: "hosting", UA: "curl"}
	b := a
	if forward.Decide(&a) != backward.Decide(&b) {
		t.Error("the decisions diverged when the rules were reshuffled")
	}
}

func TestDisabledRuleDoesNotWork(t *testing.T) {
	set := buildSet(t, nil, `{"id":"off","scope":["*"],"enabled":false,"mode":"active","priority":10,
		"condition":{"field":"method","op":"eq","value":"GET"},
		"action":{"type":"block"}}`)

	r := facts.Request{Host: "example.ru", Method: "GET"}
	if d := set.Decide(&r); d.Action != proxy.ActionPass {
		t.Errorf("a disabled rule fired: %+v", d)
	}
	if len(set.All()) != 1 {
		t.Error("the disabled rule vanished from the list; it has to be shown in rules list")
	}
}

// A broken rule discards the whole set: a half-applied set looks like it
// works and is therefore more dangerous than a refusal.
func TestABrokenRuleDiscardsTheSet(t *testing.T) {
	_, err := Build([]Rule{
		parseRule(t, blockHosting),
		parseRule(t, `{"id":"bad","scope":["*"],"mode":"active","priority":1,
			"condition":{"field":"ja44","op":"eq","value":"x"},"action":{"type":"block"}}`),
	}, nil)
	if err == nil {
		t.Fatal("a set with a broken rule was built")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("the error does not name the culprit: %v", err)
	}
}

func TestInvalidRules(t *testing.T) {
	invalid := map[string]string{
		"no id":                    `{"scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}`,
		"no mode":                  `{"id":"a","scope":["*"],"priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}`,
		"foreign mode":             `{"id":"a","scope":["*"],"mode":"dry","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}`,
		"no scope":                 `{"id":"a","mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}`,
		"empty scope":              `{"id":"a","scope":[],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}`,
		"no action":                `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{}}`,
		"foreign action":           `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"captcha"}}`,
		"ratelimit without window": `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"ratelimit","limit":10}}`,
		"ratelimit without limit":  `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"ratelimit","window":"1m"}}`,
		"invalid window":           `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"ratelimit","limit":10,"window":"a minute"}}`,
		"key on a missing field":   `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"ratelimit","limit":10,"window":"1m","key":"nope"}}`,
		"key on a bool":            `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"ratelimit","limit":10,"window":"1m","key":"grease"}}`,
		"invalid status":           `{"id":"a","scope":["*"],"mode":"active","priority":1,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block","status":700}}`,
	}
	for name, s := range invalid {
		r := parseRule(t, s)
		if _, err := r.Compile(); err == nil {
			t.Errorf("%s: the rule was accepted and must not have been", name)
		}
	}
}

func TestTheSameIDTwice(t *testing.T) {
	if _, err := Build([]Rule{parseRule(t, blockHosting), parseRule(t, blockHosting)}, nil); err == nil {
		t.Error("two rules with the same id were built")
	}
}

// A clock for the limiter in tests: the time is passed in explicitly both
// here and in production.
type counter struct{ calls []string }

func (c *counter) Exceeded(key string, limit int, window time.Duration, when time.Time) bool {
	c.calls = append(c.calls, key)
	return len(c.calls) > limit
}

func TestRatelimitCountsByKey(t *testing.T) {
	c := &counter{}
	set := buildSet(t, c, `{"id":"rl","scope":["*"],"mode":"active","priority":10,
		"condition":{"field":"path","op":"prefix","value":"/api"},
		"action":{"type":"ratelimit","limit":2,"window":"1m"}}`)

	when := time.Now()
	var last proxy.Decision
	for i := 0; i < 3; i++ {
		r := facts.Request{Host: "example.ru", Path: "/api/v1", IP: "203.0.113.7", Time: when}
		last = set.Decide(&r)
	}

	if last.Action != proxy.ActionRatelimit || last.Rule != "rl" {
		t.Errorf("the third request must hit the limit: %+v", last)
	}
	// The key contains both the rule and the address: two rules over the
	// same address are counted separately.
	if !strings.HasPrefix(c.calls[0], "rl\x00") || !strings.HasSuffix(c.calls[0], "203.0.113.7") {
		t.Errorf("invalid limiter key: %q", c.calls[0])
	}
}

// Without a limiter a rate rule lets through: blocking by a count that
// does not exist is not allowed.
func TestRatelimitWithoutALimiterLetsThrough(t *testing.T) {
	set := buildSet(t, nil, `{"id":"rl","scope":["*"],"mode":"active","priority":10,
		"condition":{"field":"path","op":"prefix","value":"/api"},
		"action":{"type":"ratelimit","limit":1,"window":"1m"}}`)

	r := facts.Request{Host: "example.ru", Path: "/api/v1"}
	if d := set.Decide(&r); d.Action != proxy.ActionPass || d.Rule != "rl" {
		t.Errorf("got %+v", d)
	}
}
