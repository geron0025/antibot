// Package rules holds the rule model, its validation and its application
// to the signals of a single request.
//
// There is one rule engine in the project: both the hot path and the
// replay over history (internal/replay) call this very matcher. The pair
// "a matcher plus a translation of the rule into a database query" was
// the most fragile place of the previous generation: let them drift
// apart, and checking against history starts to lie while a human turns
// rules on by the wrong numbers.
package rules

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/geron0025/antibot/internal/facts"
)

// Condition is the condition tree in the form it lies in rules.json.
//
// A node is either composite (exactly one of all, any, not) or a
// comparison (field, op, value). Mixing is not allowed: a node with both
// all and field filled in reads two ways, and one day it will be read the
// wrong one.
type Condition struct {
	All []Condition `json:"all,omitempty"`
	Any []Condition `json:"any,omitempty"`
	Not *Condition  `json:"not,omitempty"`

	Field string          `json:"field,omitempty"`
	Op    string          `json:"op,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

// Matcher is a compiled condition. A function rather than an interface:
// it is called on every request, and an extra level of indirection is of
// no use here.
type Matcher func(*facts.Request) bool

// Compile validates the condition and turns it into a function.
//
// Everything that can be caught here must be caught here: an unknown
// field, an operator not meant for this kind, an invalid network. A
// condition that made it to the hot path yields no more errors — it
// either matches or it does not.
func (c *Condition) Compile() (Matcher, error) {
	return c.compile("condition")
}

func (c *Condition) compile(path string) (Matcher, error) {
	composites := 0
	if c.All != nil {
		composites++
	}
	if c.Any != nil {
		composites++
	}
	if c.Not != nil {
		composites++
	}
	comparison := c.Field != "" || c.Op != "" || c.Value != nil

	switch {
	case composites > 1:
		return nil, fmt.Errorf("%s: more than one of all, any, not is filled in — leave one", path)
	case composites == 1 && comparison:
		return nil, fmt.Errorf("%s: the node is composite and a comparison at once", path)
	case composites == 0 && !comparison:
		return nil, fmt.Errorf("%s: an empty condition; a condition matching everything is written out explicitly", path)
	}

	switch {
	case c.All != nil:
		return c.junction(path, "all", c.All, true)
	case c.Any != nil:
		return c.junction(path, "any", c.Any, false)
	case c.Not != nil:
		inner, err := c.Not.compile(path + ".not")
		if err != nil {
			return nil, err
		}
		return func(r *facts.Request) bool { return !inner(r) }, nil
	default:
		return compare(path, c.Field, c.Op, c.Value)
	}
}

// junction assembles all or any. An empty list is rejected: "all of
// nothing" is true and "any of nothing" is false, and neither is what a
// human meant when they left the list empty.
func (c *Condition) junction(path, name string, children []Condition, all bool) (Matcher, error) {
	if len(children) == 0 {
		return nil, fmt.Errorf("%s.%s: an empty list of conditions", path, name)
	}
	matchers := make([]Matcher, 0, len(children))
	for i := range children {
		m, err := children[i].compile(fmt.Sprintf("%s.%s[%d]", path, name, i))
		if err != nil {
			return nil, err
		}
		matchers = append(matchers, m)
	}
	if all {
		return func(r *facts.Request) bool {
			for _, m := range matchers {
				if !m(r) {
					return false
				}
			}
			return true
		}, nil
	}
	return func(r *facts.Request) bool {
		for _, m := range matchers {
			if m(r) {
				return true
			}
		}
		return false
	}, nil
}

// Operators lists the operators allowed for a field kind. The order is
// for error messages and for the CLI hint.
func Operators(kind facts.Kind) []string {
	switch kind {
	case facts.KindNumber:
		return []string{"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in"}
	case facts.KindBool:
		return []string{"eq", "ne"}
	case facts.KindAddr:
		return []string{"eq", "ne", "in", "not_in", "cidr", "not_cidr",
			"contains", "prefix", "suffix"}
	default:
		return []string{"eq", "ne", "in", "not_in", "contains", "prefix", "suffix"}
	}
}

func allowed(kind facts.Kind, op string) bool {
	for _, a := range Operators(kind) {
		if a == op {
			return true
		}
	}
	return false
}

func compare(path, field, op string, raw json.RawMessage) (Matcher, error) {
	if field == "" {
		return nil, fmt.Errorf("%s: no field set", path)
	}
	kind, ok := facts.FieldKind(field)
	if !ok {
		return nil, fmt.Errorf("%s: the field %q does not exist; available: %s",
			path, field, strings.Join(facts.Fields(), ", "))
	}
	if op == "" {
		return nil, fmt.Errorf("%s: no op set", path)
	}
	if !allowed(kind, op) {
		return nil, fmt.Errorf("%s: the operator %q does not apply to the field %q (%s); allowed: %s",
			path, op, field, kind, strings.Join(Operators(kind), ", "))
	}
	if raw == nil {
		return nil, fmt.Errorf("%s: no value set", path)
	}

	switch kind {
	case facts.KindBool:
		return boolCompare(path, field, op, raw)
	case facts.KindNumber:
		return numberCompare(path, field, op, raw)
	case facts.KindAddr:
		if op == "cidr" || op == "not_cidr" {
			return networks(path, field, op == "not_cidr", raw)
		}
		return stringCompare(path, field, op, raw)
	default:
		return stringCompare(path, field, op, raw)
	}
}

func boolCompare(path, field, op string, raw json.RawMessage) (Matcher, error) {
	var want bool
	if err := json.Unmarshal(raw, &want); err != nil {
		return nil, fmt.Errorf("%s: the field %q is a bool, and value is neither true nor false", path, field)
	}
	if op == "ne" {
		want = !want
	}
	return func(r *facts.Request) bool {
		v, _ := r.Value(field)
		b, _ := v.(bool)
		return b == want
	}, nil
}

func numberCompare(path, field, op string, raw json.RawMessage) (Matcher, error) {
	read := func(field string) func(*facts.Request) int {
		return func(r *facts.Request) int {
			v, _ := r.Value(field)
			n, _ := v.(int)
			return n
		}
	}(field)

	if op == "in" || op == "not_in" {
		var list []int
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("%s: the field %q is a number, and value is not a list of numbers", path, field)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s: an empty list in value", path)
		}
		set := make(map[int]struct{}, len(list))
		for _, n := range list {
			set[n] = struct{}{}
		}
		negated := op == "not_in"
		return func(r *facts.Request) bool {
			_, ok := set[read(r)]
			return ok != negated
		}, nil
	}

	var want int
	if err := json.Unmarshal(raw, &want); err != nil {
		return nil, fmt.Errorf("%s: the field %q is a number, and value is not a number", path, field)
	}
	switch op {
	case "eq":
		return func(r *facts.Request) bool { return read(r) == want }, nil
	case "ne":
		return func(r *facts.Request) bool { return read(r) != want }, nil
	case "gt":
		return func(r *facts.Request) bool { return read(r) > want }, nil
	case "gte":
		return func(r *facts.Request) bool { return read(r) >= want }, nil
	case "lt":
		return func(r *facts.Request) bool { return read(r) < want }, nil
	default:
		return func(r *facts.Request) bool { return read(r) <= want }, nil
	}
}

func stringCompare(path, field, op string, raw json.RawMessage) (Matcher, error) {
	read := func(r *facts.Request) string {
		v, _ := r.Value(field)
		s, _ := v.(string)
		return s
	}

	if op == "in" || op == "not_in" {
		var list []string
		if err := json.Unmarshal(raw, &list); err != nil {
			return nil, fmt.Errorf("%s: the field %q is a string, and value is not a list of strings", path, field)
		}
		if len(list) == 0 {
			return nil, fmt.Errorf("%s: an empty list in value", path)
		}
		// A map rather than a walk: a list of fingerprints or domains can
		// hold hundreds of values, and this is the hot path.
		set := make(map[string]struct{}, len(list))
		for _, s := range list {
			set[s] = struct{}{}
		}
		negated := op == "not_in"
		return func(r *facts.Request) bool {
			_, ok := set[read(r)]
			return ok != negated
		}, nil
	}

	var want string
	if err := json.Unmarshal(raw, &want); err != nil {
		return nil, fmt.Errorf("%s: the field %q is a string, and value is not a string", path, field)
	}
	switch op {
	case "eq":
		return func(r *facts.Request) bool { return read(r) == want }, nil
	case "ne":
		return func(r *facts.Request) bool { return read(r) != want }, nil
	case "contains":
		if want == "" {
			return nil, fmt.Errorf("%s: contains with an empty string matches everything", path)
		}
		return func(r *facts.Request) bool { return strings.Contains(read(r), want) }, nil
	case "prefix":
		if want == "" {
			return nil, fmt.Errorf("%s: prefix with an empty string matches everything", path)
		}
		return func(r *facts.Request) bool { return strings.HasPrefix(read(r), want) }, nil
	default:
		if want == "" {
			return nil, fmt.Errorf("%s: suffix with an empty string matches everything", path)
		}
		return func(r *facts.Request) bool { return strings.HasSuffix(read(r), want) }, nil
	}
}

// networks compiles cidr. The lists run into hundreds of ranges — for
// Googlebot alone there are 317 — so the addresses are laid out by
// family: an IPv4 address is not compared against IPv6 networks and vice
// versa.
func networks(path, field string, negated bool, raw json.RawMessage) (Matcher, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("%s: cidr expects a list of networks", path)
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("%s: an empty list of networks", path)
	}

	var v4, v6 []netip.Prefix
	for _, s := range list {
		network, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a network like 10.0.0.0/8: %w", path, s, err)
		}
		// Masked is there so that 10.1.2.3/8 works as 10.0.0.0/8:
		// netip.Prefix.Contains on an unmasked prefix gives something
		// other than what whoever wrote it expects.
		network = network.Masked()
		if network.Addr().Is4() {
			v4 = append(v4, network)
		} else {
			v6 = append(v6, network)
		}
	}

	return func(r *facts.Request) bool {
		v, _ := r.Value(field)
		s, _ := v.(string)
		addr, err := netip.ParseAddr(s)
		if err != nil {
			// The address is unknown — we treat it as falling into no
			// network. Negation must not turn into "matched" here:
			// otherwise a request without an address passes not_cidr
			// anywhere.
			return false
		}
		addr = addr.Unmap()
		list := v4
		if addr.Is6() {
			list = v6
		}
		for _, network := range list {
			if network.Contains(addr) {
				return !negated
			}
		}
		return negated
	}, nil
}
