package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// HashLen is how many hex characters of the digest name a rule on the
// wire: 64 bits, enough that two rules of one node never collide.
const HashLen = 16

// Hash names the rule in the aggregate instead of its id.
//
// The id is the owner's text, and it tells about the site more than the
// cloud needs: "block-office-ip". The hash is taken over what the rule
// does — its condition and action — and over nothing else: switching a
// rule to active, turning it off or renaming it keeps the name, so the
// cloud can follow one rule through its life. A rule the cloud proposed
// is recognized by the same hash; a rule the owner wrote stays a hash
// and counters.
//
// The canonical form is the JSON object {"action", "condition"} as
// rules.json holds them, empty fields left out, object keys sorted, no
// whitespace, no HTML escaping, numbers as written. The cloud computes
// the same thing; docs/*/protocol/aggregate.md has a test vector.
func (r *Rule) Hash() string {
	return HashOf(r.Condition, r.Action)
}

// HashOf is Hash for a condition and an action that are not yet a rule.
func HashOf(c Condition, a Action) string {
	raw, err := json.Marshal(struct {
		Action    Action    `json:"action"`
		Condition Condition `json:"condition"`
	}{a, c})
	if err != nil {
		// A condition value that is not JSON never compiles; there is
		// nothing sensible to name.
		return ""
	}
	canon, err := canonicalJSON(raw)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:])[:HashLen]
}

// canonicalJSON re-encodes a document with sorted keys and no
// whitespace. A condition value is kept as the owner wrote it, so a
// value object's keys and spacing would otherwise leak into the name.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
