package aggregate

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

func contextWithCancel(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithCancel(t.Context())
}

func loadSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", "aggregate.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// validate checks a document against the part of JSON Schema the
// protocol's schemas use. Deliberately small, and deliberately loud
// about a keyword it does not know: a checker that silently skipped one
// would pass everything and prove nothing.
func validate(root, s map[string]any, v any, at string) []string {
	var errs []string
	fail := func(format string, args ...any) {
		errs = append(errs, at+": "+fmt.Sprintf(format, args...))
	}

	if ref, ok := s["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/$defs/")
		def, _ := root["$defs"].(map[string]any)[name].(map[string]any)
		if def == nil {
			return []string{at + ": unknown $ref " + ref}
		}
		return validate(root, def, v, at)
	}

	keys := make([]string, 0, len(s))
	for k := range s {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		rule := s[k]
		switch k {
		case "$schema", "$id", "title", "description", "$defs", "properties", "additionalProperties":
			// Handled together with "type": "object" below.
		case "type":
			if !hasType(v, rule.(string)) {
				fail("type %T, want %s", v, rule)
			}
		case "const":
			if fmt.Sprint(v) != fmt.Sprint(rule) {
				fail("%v, want the constant %v", v, rule)
			}
		case "enum":
			found := false
			for _, e := range rule.([]any) {
				if e == v {
					found = true
				}
			}
			if !found {
				fail("%v is not one of %v", v, rule)
			}
		case "required":
			obj, _ := v.(map[string]any)
			for _, name := range rule.([]any) {
				if _, ok := obj[name.(string)]; !ok {
					fail("missing required %q", name)
				}
			}
		case "minLength", "maxLength":
			str, ok := v.(string)
			n := int(rule.(float64))
			if ok && k == "minLength" && len([]rune(str)) < n || ok && k == "maxLength" && len([]rune(str)) > n {
				fail("length %d breaks %s %d", len([]rune(str)), k, n)
			}
		case "minimum":
			if num, ok := v.(float64); ok && num < rule.(float64) {
				fail("%v below the minimum %v", num, rule)
			}
		case "maxItems":
			if arr, ok := v.([]any); ok && len(arr) > int(rule.(float64)) {
				fail("%d items, at most %v", len(arr), rule)
			}
		case "pattern":
			if str, ok := v.(string); ok && !regexp.MustCompile(rule.(string)).MatchString(str) {
				fail("%q does not match %s", str, rule)
			}
		case "format":
			if rule != "date-time" {
				fail("the checker does not know format %q", rule)
			} else if str, ok := v.(string); ok {
				if _, err := time.Parse(time.RFC3339, str); err != nil {
					fail("%q is not a date-time", str)
				}
			}
		case "items":
			arr, _ := v.([]any)
			for i, item := range arr {
				errs = append(errs, validate(root, rule.(map[string]any), item, fmt.Sprintf("%s[%d]", at, i))...)
			}
		default:
			fail("the checker does not know the keyword %q", k)
		}
	}

	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		for name, val := range obj {
			if p, ok := props[name].(map[string]any); ok {
				errs = append(errs, validate(root, p, val, at+"."+name)...)
				continue
			}
			switch extra := s["additionalProperties"].(type) {
			case bool:
				if !extra {
					errs = append(errs, fmt.Sprintf("%s: field %q is not in the schema", at, name))
				}
			case map[string]any:
				errs = append(errs, validate(root, extra, val, at+"."+name)...)
			}
		}
	}
	return errs
}

func hasType(v any, t string) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		n, ok := v.(float64)
		return ok && n == math.Trunc(n)
	case "number":
		_, ok := v.(float64)
		return ok
	}
	return false
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
