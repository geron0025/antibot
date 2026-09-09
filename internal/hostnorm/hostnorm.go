// Package hostnorm brings a host name to a single form.
//
// The only copy of this logic in the whole project. There must not be a
// second one: the route, the certificate, the rule and the event all
// have to understand a name the same way, otherwise a rule for
// "Пример.РФ" will not match an event about "xn--e1afmkfd.xn--p1ai" and
// nobody will understand why.
package hostnorm

import (
	"strings"

	"golang.org/x/net/idna"
)

// Normalize strips the port, lowercases the name and converts an
// internationalized name to punycode — which is exactly what the browser
// sends in Host and the client in SNI.
func Normalize(host string) string {
	h := strings.TrimSpace(host)

	// An address in square brackets is IPv6, with or without a port.
	if i := strings.LastIndex(h, "]"); i >= 0 {
		h = strings.TrimPrefix(h[:i], "[")
	} else if i := strings.LastIndex(h, ":"); i >= 0 && strings.Count(h, ":") == 1 {
		h = h[:i]
	}

	h = strings.TrimSuffix(h, ".")
	h = strings.ToLower(h)

	if h == "" {
		return ""
	}
	// A conversion error means a name that cannot exist; keep it as is —
	// it must not match a route anyway.
	if p, err := idna.Lookup.ToASCII(h); err == nil {
		return p
	}
	return h
}
