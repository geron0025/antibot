package aggregate

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/geron0025/antibot/internal/schemacheck"
)

func contextWithCancel(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithCancel(t.Context())
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	s, err := schemacheck.Load(filepath.Join("..", "..", "docs", "schema", "aggregate.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// validate is the shared checker, named as the tests here have always
// called it.
func validate(root, s map[string]any, v any, at string) []string {
	return schemacheck.ValidateAt(root, s, v, at)
}

// The checker must fail what it should fail, or its silence means
// nothing.
func TestSchemaCheckerCatches(t *testing.T) {
	schema := loadSchema(t)
	good := func() map[string]any {
		var doc map[string]any
		json.Unmarshal([]byte(`{"format":1,"batch":"12345678","node":"8f14e45fceea167a5a36dedd4bea2543",
			"sent_at":"2026-09-08T17:20:00Z","rows":[{"window":"2026-09-08T17:00:00Z",
			"domain":"a","ja4":"","headers":"","ua_family":"chrome","ua_matches_ja4":true,
			"net":"","rule":"","shadow":[],"requests":1,"status":{"2xx":1}}]}`), &doc)
		return doc
	}
	row := func(doc map[string]any) map[string]any {
		return doc["rows"].([]any)[0].(map[string]any)
	}

	if errs := validate(schema, schema, good(), "$"); len(errs) > 0 {
		t.Fatalf("a valid batch failed: %v", errs)
	}

	bad := map[string]func(map[string]any){
		"extra field":      func(d map[string]any) { d["extra"] = 1.0 },
		"extra row field":  func(d map[string]any) { row(d)["ip"] = "203.0.113.7" },
		"wrong family":     func(d map[string]any) { row(d)["ua_family"] = "netscape" },
		"null status":      func(d map[string]any) { row(d)["status"] = nil },
		"negative count":   func(d map[string]any) { row(d)["requests"] = -1.0 },
		"window not date":  func(d map[string]any) { row(d)["window"] = "~rest" },
		"rest as boolean":  func(d map[string]any) { row(d)["ua_matches_ja4"] = "~rest" },
		"long domain":      func(d map[string]any) { row(d)["domain"] = strings.Repeat("a", 254) },
		"missing required": func(d map[string]any) { delete(row(d), "net") },
		"bad node":         func(d map[string]any) { d["node"] = "NODE" },
		"wrong format":     func(d map[string]any) { d["format"] = 2.0 },
		"missing rule":     func(d map[string]any) { delete(row(d), "rule") },
		"long rule":        func(d map[string]any) { row(d)["rule"] = strings.Repeat("r", 65) },
		"shadow not array": func(d map[string]any) { row(d)["shadow"] = "watch-1" },
		"too many shadow": func(d map[string]any) {
			list := make([]any, maxShadow+1)
			for i := range list {
				list[i] = "watch"
			}
			row(d)["shadow"] = list
		},
		"too many rows": func(d map[string]any) {
			rows := make([]any, MaxRows+1)
			for i := range rows {
				rows[i] = row(d)
			}
			d["rows"] = rows
		},
	}
	for name, mutate := range bad {
		doc := good()
		mutate(doc)
		if errs := validate(schema, schema, doc, "$"); len(errs) == 0 {
			t.Errorf("%s passed the checker", name)
		}
	}
}
