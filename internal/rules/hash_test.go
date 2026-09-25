package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/facts"
)

// hashVector is the test vector of docs/*/protocol/aggregate.md. The
// cloud checks the same pair: a hash that drifted on one side would
// quietly stop the cloud from recognizing its own proposals.
const (
	hashVectorRule = `{"id": "block-hosting-go", "scope": ["*"], "mode": "shadow", "priority": 10,
		"condition": {"all": [
			{"field": "network.class", "op": "eq", "value": "hosting"},
			{"field": "family", "op": "eq", "value": "go"}]},
		"action": {"type": "block", "status": 403}}`
	hashVector = "50c32b7c35cdaae8"
)

func ruleOf(t *testing.T, raw string) Rule {
	t.Helper()
	var r Rule
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestHashVector(t *testing.T) {
	r := ruleOf(t, hashVectorRule)
	if h := r.Hash(); h != hashVector {
		t.Errorf("hash %s, want %s", h, hashVector)
	}
}

// What the owner changes in a rule's life — its id, name, mode, whether
// it is on, its priority and scope — keeps its name; what the rule does
// changes it.
func TestHashFollowsWhatTheRuleDoes(t *testing.T) {
	base := ruleOf(t, hashVectorRule)
	same := ruleOf(t, `{"id": "x", "name": "другое", "scope": ["shop.example.ru"],
		"mode": "active", "enabled": false, "priority": 900,
		"condition": {"all": [
			{"value": "hosting", "op": "eq", "field": "network.class"},
			{"field": "family", "op": "eq", "value":   "go"}]},
		"action": {"status": 403, "type": "block"}}`)
	if base.Hash() != same.Hash() {
		t.Errorf("the same rule, two names: %s and %s", base.Hash(), same.Hash())
	}

	other := base
	other.Action.Status = 429
	if other.Hash() == base.Hash() {
		t.Error("another answer, the same name")
	}
	other = ruleOf(t, hashVectorRule)
	other.Condition.All[1].Value = json.RawMessage(`"python"`)
	if other.Hash() == base.Hash() {
		t.Error("another condition, the same name")
	}
}

// A rule is named on the wire by its hash, and Decide says it.
func TestDecideCarriesTheHash(t *testing.T) {
	r := ruleOf(t, hashVectorRule)
	w := r
	w.ID, w.Mode, w.Priority = "watch", Shadow, 20
	w.Action.Status = 404
	r.ID, r.Mode = "block", Active
	set, err := Build([]Rule{r, w}, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := &facts.Request{Host: "example.ru", NetClass: "hosting", Family: "go"}
	d := set.Decide(req)
	if d.RuleHash != hashVector || len(req.ShadowHashes) != 1 || req.ShadowHashes[0] != w.Hash() {
		t.Errorf("decision %+v, shadow hashes %v", d, req.ShadowHashes)
	}
}

// The test vector in the protocol document is this one, in both
// languages: the cloud is written from the document.
func TestHashVectorInDocs(t *testing.T) {
	fence := regexp.MustCompile("(?s)```json rule-hash\n(.*?)```")
	for _, lang := range []string{"ru", "en"} {
		path := filepath.Join("..", "..", "docs", lang, "protocol", "aggregate.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		m := fence.FindSubmatch(raw)
		if m == nil {
			t.Fatalf("%s: no rule-hash example", path)
		}
		r := ruleOf(t, string(m[1]))
		if h := r.Hash(); h != hashVector {
			t.Errorf("%s: the example hashes to %s, want %s", path, h, hashVector)
		}
		if !strings.Contains(string(raw), "`"+hashVector+"`") {
			t.Errorf("%s: the hash %s is not named", path, hashVector)
		}
	}
}
