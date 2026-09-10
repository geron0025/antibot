// Package proxy routes a request to an upstream, determines the client's
// real address and collects the signals of the request.
package proxy

import (
	"strings"

	"github.com/geron0025/antibot/internal/hostnorm"
)

// Router picks an upstream by host name.
//
// Three forms, in decreasing order of precision:
//
//	shop.example.ru      an exact name
//	*.example.ru         any subdomain of any depth, but not example.ru itself
//	*                    the default route
//
// The exact match is chosen first, then the longest matching pattern, and
// only after that the default. That is why the order of lines in the
// configuration changes nothing — the "whoever is higher wins" rule in
// route configuration has been catching people out for decades.
type Router struct {
	exact    map[string]string
	patterns []pattern
	fallback string
}

type pattern struct {
	suffix string // ".example.ru"
	to     string
}

// NewRouter builds a router. The "name → address" pairs arrive in any
// order.
func NewRouter(routes map[string]string) *Router {
	r := &Router{exact: make(map[string]string)}

	for name, to := range routes {
		switch {
		case name == "*":
			r.fallback = to
		case strings.HasPrefix(name, "*."):
			// The name is normalized without the leading dot: with it the
			// punycode conversion sees an empty label and returns the
			// string unchanged, and the dot is then appended a second
			// time.
			tail := hostnorm.Normalize(name[2:])
			r.patterns = append(r.patterns, pattern{suffix: "." + tail, to: to})
		default:
			r.exact[hostnorm.Normalize(name)] = to
		}
	}
	return r
}

// To returns the upstream address and whether a route was found.
func (r *Router) To(host string) (string, bool) {
	h := hostnorm.Normalize(host)
	if h == "" {
		return r.fallback, r.fallback != ""
	}

	if to, ok := r.exact[h]; ok {
		return to, true
	}

	// The longest matching suffix: for a.b.example.ru the pattern
	// *.b.example.ru is more precise than *.example.ru.
	var best pattern
	for _, p := range r.patterns {
		if !strings.HasSuffix(h, p.suffix) {
			continue
		}
		if len(p.suffix) > len(best.suffix) {
			best = p
		}
	}
	if best.to != "" {
		return best.to, true
	}

	return r.fallback, r.fallback != ""
}

// Named reports whether the host is served by a route that names it —
// exactly or by a pattern. The default route does not count: it takes
// whatever the client puts into Host, and the aggregate must not carry
// a scanner's made-up names to the cloud as "protected domains".
func (r *Router) Named(host string) bool {
	h := hostnorm.Normalize(host)
	if h == "" {
		return false
	}
	if _, ok := r.exact[h]; ok {
		return true
	}
	for _, p := range r.patterns {
		if strings.HasSuffix(h, p.suffix) {
			return true
		}
	}
	return false
}

// Names lists the exact names the node serves. Needed for issuing
// certificates and for checking rules with a scope.
func (r *Router) Names() []string {
	out := make([]string, 0, len(r.exact))
	for name := range r.exact {
		out = append(out, name)
	}
	return out
}
