package rules

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/facts"
)

func compileCondition(t *testing.T, s string) Matcher {
	t.Helper()
	var c Condition
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		t.Fatalf("parsing JSON: %v", err)
	}
	m, err := c.Compile()
	if err != nil {
		t.Fatalf("compiling %s: %v", s, err)
	}
	return m
}

func sample() facts.Request {
	return facts.Request{
		IP: "203.0.113.7", Host: "example.ru", Method: "GET",
		Path: "/catalog/page", UA: "Mozilla/5.0 Chrome/152",
		JA4:         "t13d1516h2_8daaf6152771_02713d6af862",
		HeadersHash: "bb0c31243d649b46", GREASE: true,
		NetClass: "hosting", NetAge: 42, UAMatchesJA4: false,
	}
}

func TestComparisons(t *testing.T) {
	r := sample()

	checks := []struct {
		condition string
		want      bool
	}{
		{`{"field":"host","op":"eq","value":"example.ru"}`, true},
		{`{"field":"host","op":"eq","value":"other.ru"}`, false},
		{`{"field":"host","op":"ne","value":"other.ru"}`, true},
		{`{"field":"ua","op":"contains","value":"Chrome"}`, true},
		{`{"field":"ua","op":"contains","value":"Firefox"}`, false},
		{`{"field":"path","op":"prefix","value":"/catalog"}`, true},
		{`{"field":"path","op":"suffix","value":"/page"}`, true},
		{`{"field":"ja4","op":"in","value":["a","t13d1516h2_8daaf6152771_02713d6af862"]}`, true},
		{`{"field":"ja4","op":"not_in","value":["a","b"]}`, true},

		// An empty string is an ordinary value, not "unset". The caveat
		// "the client did not identify itself" rests on it, and in the
		// previous project it stood in nearly every rule.
		{`{"field":"referer","op":"eq","value":""}`, true},
		{`{"field":"sni","op":"ne","value":""}`, false},

		{`{"field":"grease","op":"eq","value":true}`, true},
		{`{"field":"grease","op":"ne","value":true}`, false},
		{`{"field":"ua_matches_ja4","op":"eq","value":false}`, true},

		{`{"field":"network.age","op":"gt","value":40}`, true},
		{`{"field":"network.age","op":"gte","value":42}`, true},
		{`{"field":"network.age","op":"lt","value":42}`, false},
		{`{"field":"network.age","op":"lte","value":42}`, true},
		{`{"field":"network.age","op":"in","value":[1,42]}`, true},

		{`{"field":"ip","op":"cidr","value":["203.0.113.0/24"]}`, true},
		{`{"field":"ip","op":"cidr","value":["198.51.100.0/24"]}`, false},
		{`{"field":"ip","op":"not_cidr","value":["198.51.100.0/24"]}`, true},
		// An unmasked network must work the way a human reads it:
		// 203.0.113.7/24 is 203.0.113.0/24.
		{`{"field":"ip","op":"cidr","value":["203.0.113.7/24"]}`, true},
		// Networks of another family must match nothing.
		{`{"field":"ip","op":"cidr","value":["2001:db8::/32"]}`, false},

		{`{"all":[{"field":"network.class","op":"eq","value":"hosting"},
		          {"field":"ua_matches_ja4","op":"eq","value":false}]}`, true},
		{`{"all":[{"field":"network.class","op":"eq","value":"hosting"},
		          {"field":"grease","op":"eq","value":false}]}`, false},
		{`{"any":[{"field":"network.class","op":"eq","value":"residential"},
		          {"field":"headers_hash","op":"eq","value":"bb0c31243d649b46"}]}`, true},
		{`{"not":{"field":"host","op":"eq","value":"example.ru"}}`, false},
	}

	for _, c := range checks {
		if got := compileCondition(t, c.condition)(&r); got != c.want {
			t.Errorf("%s: got %v, want %v", c.condition, got, c.want)
		}
	}
}

// Everything that will never match has to be a parse error: a condition
// that silently does not fire looks like a working rule.
func TestInvalidConditions(t *testing.T) {
	invalid := map[string]string{
		"unknown field":            `{"field":"ja44","op":"eq","value":"x"}`,
		"typo in the operator":     `{"field":"ua","op":"equals","value":"x"}`,
		"cidr over a string":       `{"field":"ua","op":"cidr","value":["10.0.0.0/8"]}`,
		"contains over a number":   `{"field":"network.age","op":"contains","value":"4"}`,
		"gt over a string":         `{"field":"ua","op":"gt","value":"x"}`,
		"string instead of number": `{"field":"network.age","op":"eq","value":"forty"}`,
		"string instead of bool":   `{"field":"grease","op":"eq","value":"true"}`,
		"number instead of string": `{"field":"ua","op":"eq","value":7}`,
		"invalid network":          `{"field":"ip","op":"cidr","value":["10.0.0.0/33"]}`,
		"address instead of net":   `{"field":"ip","op":"cidr","value":["10.0.0.1"]}`,
		"empty list of networks":   `{"field":"ip","op":"cidr","value":[]}`,
		"empty list of values":     `{"field":"ja4","op":"in","value":[]}`,
		"empty condition":          `{}`,
		"empty all":                `{"all":[]}`,
		"composite and comparison": `{"all":[{"field":"ua","op":"eq","value":"x"}],"field":"host","op":"eq","value":"y"}`,
		"two composites":           `{"all":[{"field":"ua","op":"eq","value":"x"}],"any":[{"field":"ua","op":"eq","value":"y"}]}`,
		"contains with empty":      `{"field":"ua","op":"contains","value":""}`,
		"no value":                 `{"field":"ua","op":"eq"}`,
		"no op":                    `{"field":"ua","value":"x"}`,
		"error in the depths":      `{"all":[{"any":[{"not":{"field":"nope","op":"eq","value":"x"}}]}]}`,
	}

	for name, s := range invalid {
		var c Condition
		if err := json.Unmarshal([]byte(s), &c); err != nil {
			continue // invalid JSON is a refusal too, but the check is what we are after
		}
		if _, err := c.Compile(); err == nil {
			t.Errorf("%s: %s was accepted and must not have been", name, s)
		}
	}
}

// An error message must name the place and list what is available: a
// human reads it at the moment their rule failed to take effect.
func TestErrorNamesThePlace(t *testing.T) {
	var c Condition
	if err := json.Unmarshal([]byte(`{"all":[{"field":"host","op":"eq","value":"a"},
	                                          {"field":"ja44","op":"eq","value":"b"}]}`), &c); err != nil {
		t.Fatal(err)
	}
	_, err := c.Compile()
	if err == nil {
		t.Fatal("an unknown field was accepted")
	}
	if !strings.Contains(err.Error(), "condition.all[1]") {
		t.Errorf("the error carries no place: %v", err)
	}
	if !strings.Contains(err.Error(), "ja4") {
		t.Errorf("the error carries no list of available fields: %v", err)
	}
}

// Every field must have at least one working operator, otherwise the
// field is declared but no rule can be written against it.
func TestEveryFieldHasOperators(t *testing.T) {
	for _, field := range facts.Fields() {
		kind, _ := facts.FieldKind(field)
		if len(Operators(kind)) == 0 {
			t.Errorf("field %q (%s) has no operators", field, kind)
		}
	}
}
