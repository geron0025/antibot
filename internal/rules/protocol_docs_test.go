package rules

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/schemacheck"
)

// Every example in the proposals document matches its schema — the list
// of proposals and advice going down, the node's feedback going up — in
// both languages. Nothing in the node reads these yet; the examples are
// what the cloud is written from, and a drifted one is a wrong spec.
func TestProposalDocExamplesMatchTheSchemas(t *testing.T) {
	load := func(name string) map[string]any {
		s, err := schemacheck.Load(filepath.Join("..", "..", "docs", "schema", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	proposals, feedback := load("proposals"), load("proposal-feedback")

	for _, lang := range []string{"ru", "en"} {
		path := filepath.Join("..", "..", "docs", lang, "protocol", "proposals.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]int{}
		for _, m := range jsonBlock.FindAllStringSubmatch(string(raw), -1) {
			var doc map[string]any
			if err := json.Unmarshal([]byte(strings.TrimSpace(m[1])), &doc); err != nil {
				continue
			}
			var schema map[string]any
			switch {
			case doc["proposals"] != nil:
				schema = proposals
				if doc["advice"] != nil {
					seen["advice"]++
				}
			case doc["items"] != nil:
				schema, seen["feedback"] = feedback, seen["feedback"]+1
			default:
				continue
			}
			seen["all"]++
			if errs := schemacheck.Validate(schema, doc); len(errs) > 0 {
				t.Errorf("%s: an example does not match its schema:\n%s", path, strings.Join(errs, "\n"))
			}
		}
		if seen["all"] < 3 || seen["advice"] == 0 || seen["feedback"] == 0 {
			t.Errorf("%s: examples found %v; want the proposals, the advice and the feedback", path, seen)
		}
	}
}

// The schemas refuse what the channel must not carry: a mode in a
// proposal, a rule in advice, an owner's id in place of a hash.
func TestProposalSchemasRefuse(t *testing.T) {
	load := func(name string) map[string]any {
		s, err := schemacheck.Load(filepath.Join("..", "..", "docs", "schema", name+".schema.json"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	advice := func(mut func(map[string]any)) map[string]any {
		a := map[string]any{
			"id": "cloud-advice-x", "created_at": "2026-09-09T04:00:00Z",
			"expires_at": "2026-09-23T00:00:00Z", "rule": hashVector, "suggest": "disable",
			"why": "w", "evidence": map[string]any{"window": "w", "requests": 1.0, "share": 0.1},
		}
		mut(a)
		return map[string]any{"format": 1.0, "node": strings.Repeat("a", 32),
			"created_at": "2026-09-09T04:00:00Z", "proposals": []any{}, "advice": []any{a}}
	}
	proposals := load("proposals")
	if errs := schemacheck.Validate(proposals, advice(func(map[string]any) {})); len(errs) > 0 {
		t.Fatalf("the baseline advice is refused: %v", errs)
	}
	for name, mut := range map[string]func(map[string]any){
		"id for a hash":  func(a map[string]any) { a["rule"] = "block-office-ip" },
		"a rule inside":  func(a map[string]any) { a["condition"] = map[string]any{} },
		"a mode":         func(a map[string]any) { a["mode"] = "active" },
		"unknown advice": func(a map[string]any) { a["suggest"] = "delete" },
	} {
		if errs := schemacheck.Validate(proposals, advice(mut)); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}

	feedback := load("proposal-feedback")
	item := func(mut func(map[string]any)) map[string]any {
		i := map[string]any{"id": "cloud-x", "state": "rejected", "at": "2026-09-10T09:05:00Z"}
		mut(i)
		return map[string]any{"format": 1.0, "node": strings.Repeat("a", 32),
			"sent_at": "2026-09-12T10:00:00Z", "items": []any{i}}
	}
	if errs := schemacheck.Validate(feedback, item(func(map[string]any) {})); len(errs) > 0 {
		t.Fatalf("the baseline feedback is refused: %v", errs)
	}
	for name, mut := range map[string]func(map[string]any){
		"owner's rule":  func(i map[string]any) { i["id"] = "block-office-ip" },
		"visitor data":  func(i map[string]any) { i["ip"] = "203.0.113.1" },
		"long reason":   func(i map[string]any) { i["reason"] = strings.Repeat("я", 501) },
		"unknown state": func(i map[string]any) { i["state"] = "maybe" },
		"id for a hash": func(i map[string]any) { i["rule"] = "block-office-ip" },
	} {
		if errs := schemacheck.Validate(feedback, item(mut)); len(errs) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
