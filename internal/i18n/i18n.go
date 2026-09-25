// Package i18n translates a user interface: catalogs of messages per
// language, positional arguments, plural forms and the formats of numbers
// and dates.
//
// It is the node's own and depends on nothing: two languages need the
// plural rules of two languages, which are a few lines, and pulling a
// library for them into a program that is installed on somebody else's
// server is not worth it.
//
// A catalog is a JSON file per language, <lang>.json, with flat keys. A
// value is a string, or an object of plural forms for a message that
// depends on a count. Arguments are positional — {0}, {1} — because word
// order differs between languages, and a Go template has no way to pass
// names other than as pairs.
//
// A catalog is checked as it loads: every language has the keys of the
// source language, every plural message has every form its language
// needs, and a translation uses the same arguments as the source. A
// mismatch is an error rather than a hole found by a user.
package i18n

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Lang is a language code: "en", "ru".
type Lang string

const (
	EN Lang = "en"
	RU Lang = "ru"
)

// Supported are the languages the package knows the plural rules and the
// formats of. A catalog file of any other language is an error.
var Supported = []Lang{EN, RU}

// Parse reads a language code, accepting only the supported ones.
func Parse(s string) (Lang, bool) {
	for _, l := range Supported {
		if string(l) == s {
			return l, true
		}
	}
	return "", false
}

// Catalog is the messages of every language, loaded and checked.
type Catalog struct {
	source   Lang
	printers map[Lang]*Printer
}

// Load reads every <lang>.json at the root of fsys. source is the
// language the others are checked against; it must be among the files.
func Load(fsys fs.FS, source Lang) (*Catalog, error) {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	c := &Catalog{source: source, printers: map[Lang]*Printer{}}
	for _, name := range names {
		lang, ok := Parse(strings.TrimSuffix(path.Base(name), ".json"))
		if !ok {
			return nil, fmt.Errorf("%s: the language is not one of %v", name, Supported)
		}
		contents, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		messages, err := parseCatalog(lang, contents)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		c.printers[lang] = &Printer{lang: lang, messages: messages}
	}
	src, ok := c.printers[source]
	if !ok {
		return nil, fmt.Errorf("no catalog of the source language, %s.json", source)
	}
	for lang, p := range c.printers {
		if lang == source {
			continue
		}
		if err := compare(src.messages, p.messages); err != nil {
			return nil, fmt.Errorf("%s.json: %w", lang, err)
		}
	}
	return c, nil
}

func parseCatalog(lang Lang, contents []byte) (map[string]message, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(contents, &raw); err != nil {
		return nil, err
	}
	messages := make(map[string]message, len(raw))
	for key, value := range raw {
		var text string
		if err := json.Unmarshal(value, &text); err == nil {
			messages[key] = message{text: text}
			continue
		}
		var forms map[string]string
		if err := json.Unmarshal(value, &forms); err != nil {
			return nil, fmt.Errorf("%q is neither a string nor an object of plural forms", key)
		}
		need := pluralForms[lang]
		for _, form := range need {
			if _, ok := forms[form]; !ok {
				return nil, fmt.Errorf("%q lacks the plural form %q", key, form)
			}
		}
		for form := range forms {
			if !slices.Contains(need, form) {
				return nil, fmt.Errorf("%q has the plural form %q, which %s does not use", key, form, lang)
			}
		}
		messages[key] = message{forms: forms}
	}
	return messages, nil
}

// compare checks a translation against the source: the same keys, plural
// where the source is plural, the same arguments.
func compare(source, translation map[string]message) error {
	for _, key := range sortedKeys(source) {
		m, ok := translation[key]
		if !ok {
			return fmt.Errorf("%q is missing", key)
		}
		if (source[key].forms == nil) != (m.forms == nil) {
			return fmt.Errorf("%q is plural in one language and not in the other", key)
		}
		want, got := source[key].args(), m.args()
		for arg := range got {
			if _, ok := want[arg]; !ok {
				return fmt.Errorf("%q uses {%d}, which the source does not pass", key, arg)
			}
		}
		for arg := range want {
			if _, ok := got[arg]; !ok {
				return fmt.Errorf("%q loses {%d}, which the source uses", key, arg)
			}
		}
	}
	for _, key := range sortedKeys(translation) {
		if _, ok := source[key]; !ok {
			return fmt.Errorf("%q is not in the source", key)
		}
	}
	return nil
}

func sortedKeys(m map[string]message) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// Langs lists the languages of the catalog, the source first.
func (c *Catalog) Langs() []Lang {
	out := []Lang{c.source}
	for _, l := range Supported {
		if _, ok := c.printers[l]; ok && l != c.source {
			out = append(out, l)
		}
	}
	return out
}

// Keys lists every key of the catalog, sorted.
func (c *Catalog) Keys() []string {
	return sortedKeys(c.printers[c.source].messages)
}

// Printer is the catalog's messages in one language; a language the
// catalog does not have gets the source language.
func (c *Catalog) Printer(l Lang) *Printer {
	if p, ok := c.printers[l]; ok {
		return p
	}
	return c.printers[c.source]
}

// Printer renders messages, numbers and dates in one language.
type Printer struct {
	lang     Lang
	messages map[string]message
}

// message is a plain text, or the plural forms of one.
type message struct {
	text  string
	forms map[string]string
}

var argPattern = regexp.MustCompile(`\{(\d+)\}`)

// args are the argument numbers the message uses, in any of its forms.
func (m message) args() map[int]struct{} {
	texts := []string{m.text}
	for _, form := range m.forms {
		texts = append(texts, form)
	}
	out := map[int]struct{}{}
	for _, text := range texts {
		for _, match := range argPattern.FindAllStringSubmatch(text, -1) {
			n, _ := strconv.Atoi(match[1])
			out[n] = struct{}{}
		}
	}
	return out
}

// Lang is the printer's language.
func (p *Printer) Lang() Lang { return p.lang }

// T renders a message. An integer argument is printed as a number of the
// language; a key the catalog does not have is printed as the key itself,
// so that a missing translation shows rather than breaks the page.
func (p *Printer) T(key string, args ...any) string {
	m, ok := p.messages[key]
	if !ok || m.forms != nil {
		return key
	}
	return p.fill(m.text, args)
}

// N renders a message that depends on the count n: the form is chosen by
// the plural rules of the language, n itself is {0}, and args follow it
// as {1}, {2}….
func (p *Printer) N(key string, n int, args ...any) string {
	m, ok := p.messages[key]
	if !ok || m.forms == nil {
		return key
	}
	return p.fill(m.forms[pluralForm(p.lang, n)], append([]any{n}, args...))
}

// fill puts the arguments in place of {0}, {1}…; a number without an
// argument stays as it is.
func (p *Printer) fill(text string, args []any) string {
	if !strings.Contains(text, "{") {
		return text
	}
	return argPattern.ReplaceAllStringFunc(text, func(match string) string {
		n, _ := strconv.Atoi(match[1 : len(match)-1])
		if n >= len(args) {
			return match
		}
		return p.arg(args[n])
	})
}

func (p *Printer) arg(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case int:
		return p.Number(int64(v))
	case int64:
		return p.Number(v)
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}
