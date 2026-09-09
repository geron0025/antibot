// Package headersfp computes a fingerprint from the composition of the
// request headers.
//
// The value is not in the values but in the set and the order: a browser
// sends its own set in a stable order fixed by its code, while a
// hand-written client sends the one its author listed. The two cannot
// coincide by accident.
package headersfp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"slices"
	"strings"
)

// Volatile headers are excluded from the fingerprint: they depend on the
// page and on intermediaries along the way rather than on the client,
// and without this the same browser would produce a different
// fingerprint on different pages of the site.
var volatile = map[string]bool{
	"content-length":    true,
	"cookie":            true,
	"host":              true,
	"if-none-match":     true,
	"if-modified-since": true,
	"range":             true,
	"referer":           true,
	"authorization":     true,
}

// Names returns the header names in the order they arrived, lowercased
// and with the volatile ones removed.
//
// The order is passed in ready-made, because only whoever read the
// request knows it: http.Request.Header does not preserve order at all,
// and Go's map iteration is deliberately randomized.
func Names(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		n := strings.ToLower(name)
		if volatile[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}

// Fingerprint is the comma-separated names plus their hash.
type Fingerprint struct {
	Names string
	Hash  string
}

// Compute builds a fingerprint from an ordered list of names.
func Compute(names []string) Fingerprint {
	s := strings.Join(Names(names), ",")
	if s == "" {
		return Fingerprint{}
	}
	sum := sha256.Sum256([]byte(s))
	return Fingerprint{Names: s, Hash: hex.EncodeToString(sum[:])[:16]}
}

// FromHTTP1Request recovers the header order from an HTTP/1.1 request.
//
// In HTTP/1.1 the order can only be recovered from the raw bytes, which
// net/http does not keep, so the alphabetical order of the map keys is
// used here — that is, the **composition without the order**. This is an
// honest limitation: for HTTP/2 the order is known exactly, and the
// fingerprint is stronger there.
func FromHTTP1Request(r *http.Request) Fingerprint {
	names := make([]string, 0, len(r.Header))
	for name := range r.Header {
		names = append(names, name)
	}
	slices.SortFunc(names, func(a, b string) int {
		return strings.Compare(strings.ToLower(a), strings.ToLower(b))
	})
	return Compute(names)
}
