package rules

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

// docPages are the documents whose examples must stay valid.
//
// Both language trees are listed: a translated example that drifted from
// the code is exactly as wrong as an original one, and nobody rereads a
// translation looking for compile errors.
var docPages = []string{
	"../../README.md",
	"../../docs/ru/README.md",
	"../../docs/ru/rules.md",
	"../../docs/ru/facts.md",
	"../../docs/ru/protocol/proposals.md",
	"../../docs/en/rules.md",
	"../../docs/en/facts.md",
	"../../docs/en/protocol/proposals.md",
}

var jsonBlock = regexp.MustCompile("(?s)```json\n(.*?)```")

// blocks returns the JSON examples of a page, skipping fragments that do
// not parse: a document may show an ellipsis on purpose.
func blocks(t *testing.T, path string) []map[string]json.RawMessage {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []map[string]json.RawMessage
	for _, m := range jsonBlock.FindAllStringSubmatch(string(contents), -1) {
		var doc map[string]json.RawMessage
		if err := json.Unmarshal([]byte(strings.TrimSpace(m[1])), &doc); err != nil {
			continue
		}
		out = append(out, doc)
	}
	return out
}

// A rule example in the documentation must compile with this engine.
//
// A document that has drifted from the code is worse than none: people
// write rules by it that fail to take effect, and they blame the node.
//
// Examples are allowed to omit scope and mode — a page explaining
// priority should not have to repeat the whole rule — so the defaults are
// filled in before compiling. Everything else is checked as written.
func TestRuleExamplesInDocs(t *testing.T) {
	checked := 0

	for _, page := range docPages {
		for _, doc := range blocks(t, page) {
			if _, ok := doc["condition"]; !ok {
				continue
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}

			var r Rule
			decoder := json.NewDecoder(strings.NewReader(string(raw)))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&r); err != nil {
				t.Errorf("%s: an example does not parse: %v\n%s", page, err, raw)
				continue
			}
			if len(r.Scope) == 0 {
				r.Scope = []string{"*"}
			}
			if r.Mode == "" {
				r.Mode = Shadow
			}
			if _, err := r.Compile(); err != nil {
				t.Errorf("%s: an example did not compile: %v\n%s", page, err, raw)
				continue
			}
			checked++
		}
	}

	if checked == 0 {
		t.Error("no rule example was found in the documentation — there is nothing to check")
	}
}

// A bare condition shown in the documentation must compile too. Those
// appear where a page explains a field rather than a whole rule.
func TestConditionExamplesInDocs(t *testing.T) {
	checked := 0

	for _, page := range docPages {
		for _, doc := range blocks(t, page) {
			composite := false
			for _, key := range []string{"all", "any", "not", "field"} {
				if _, ok := doc[key]; ok {
					composite = true
				}
			}
			if !composite {
				continue
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}

			var c Condition
			if err := json.Unmarshal(raw, &c); err != nil {
				t.Errorf("%s: a condition does not parse: %v", page, err)
				continue
			}
			if _, err := c.Compile(); err != nil {
				t.Errorf("%s: a condition did not compile: %v\n%s", page, err, raw)
				continue
			}
			checked++
		}
	}

	if checked == 0 {
		t.Error("no condition example was found in the documentation")
	}
}

// The actions and modes named in the README must exist in the code.
func TestREADMENamesWhatExists(t *testing.T) {
	contents, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Skipf("the README was not read: %v", err)
	}
	text := string(contents)

	for _, word := range []string{Block, Allow, Ratelimit, Shadow, Active} {
		if !strings.Contains(text, word) {
			t.Errorf("the README does not mention %q — either the document lags behind or the code is superfluous", word)
		}
	}
}

// The rule inside a proposal from the protocol document must compile with
// this very engine.
//
// A proposal carries no mode: the node substitutes shadow when a human
// accepts it, and there is nowhere else for the value to come from. So
// the check adds shadow and compiles what is left — exactly what the node
// will do. A protocol document that has drifted from the engine is worse
// than none: the cloud would build proposals nobody can accept.
func TestProposalExampleCompiles(t *testing.T) {
	pages := []string{
		"../../docs/ru/protocol/proposals.md",
		"../../docs/en/protocol/proposals.md",
	}
	checked := 0

	for _, page := range pages {
		contents, err := os.ReadFile(page)
		if err != nil {
			t.Errorf("%s was not read: %v", page, err)
			continue
		}
		for _, block := range jsonBlock.FindAllStringSubmatch(string(contents), -1) {
			text := strings.TrimSpace(block[1])
			if !strings.Contains(text, `"proposals"`) {
				continue
			}

			var doc struct {
				Proposals []struct {
					ID   string          `json:"id"`
					Rule json.RawMessage `json:"rule"`
				} `json:"proposals"`
			}
			if err := json.Unmarshal([]byte(text), &doc); err != nil {
				t.Fatalf("the proposal example does not parse: %v", err)
			}

			for _, p := range doc.Proposals {
				// The id prefix is what tells a proposed rule from one the
				// owner wrote, in `antibot rules list` and everywhere else.
				if !strings.HasPrefix(p.ID, "cloud-") {
					t.Errorf("the proposal %q lacks the cloud- prefix", p.ID)
				}

				var r Rule
				decoder := json.NewDecoder(strings.NewReader(string(p.Rule)))
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&r); err != nil {
					t.Errorf("the rule of proposal %q does not parse: %v", p.ID, err)
					continue
				}
				// A proposal must not be able to express a mode at all.
				if r.Mode != "" {
					t.Errorf("the rule of proposal %q carries a mode: %q", p.ID, r.Mode)
				}
				r.Mode = Shadow

				if _, err := r.Compile(); err != nil {
					t.Errorf("the rule of proposal %q did not compile: %v", p.ID, err)
					continue
				}
				checked++
			}
		}
	}

	if checked == 0 {
		t.Error("no proposal example was found in the protocol documents")
	}
}
