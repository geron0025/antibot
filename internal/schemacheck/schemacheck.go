// Package schemacheck checks a document against the part of JSON Schema
// the node's published schemas use — the protocol's and the API's.
//
// Deliberately small, and deliberately loud about a keyword it does not
// know: a checker that silently skipped one would pass everything and
// prove nothing. It serves the tests that hold the schemas and the code to
// each other; the node itself never validates against a schema at run
// time.
package schemacheck

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Load reads a schema file.
func Load(path string) (map[string]any, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("schema %s: %w", path, err)
	}
	return s, nil
}

// Validate checks a decoded document against the whole schema and returns
// what is wrong, a line per fault. Nothing means the document fits.
func Validate(schema map[string]any, v any) []string {
	return ValidateAt(schema, schema, v, "$")
}

// ValidateAt checks v against the part s of the schema root, naming the
// place in the document as at.
func ValidateAt(root, s map[string]any, v any, at string) []string {
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
		return ValidateAt(root, def, v, at)
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
				errs = append(errs, ValidateAt(root, rule.(map[string]any), item, fmt.Sprintf("%s[%d]", at, i))...)
			}
		default:
			fail("the checker does not know the keyword %q", k)
		}
	}

	if obj, ok := v.(map[string]any); ok {
		props, _ := s["properties"].(map[string]any)
		for name, val := range obj {
			if p, ok := props[name].(map[string]any); ok {
				errs = append(errs, ValidateAt(root, p, val, at+"."+name)...)
				continue
			}
			switch extra := s["additionalProperties"].(type) {
			case bool:
				if !extra {
					errs = append(errs, fmt.Sprintf("%s: field %q is not in the schema", at, name))
				}
			case map[string]any:
				errs = append(errs, ValidateAt(root, extra, val, at+"."+name)...)
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
