package proxy

import "sync/atomic"

// RouteTable is the router currently in force.
//
// It exists so that a domain added while the node runs takes effect
// without a restart: the hot path reads the router through one atomic
// pointer, and a change swaps the router whole. The Router itself stays
// immutable — rebuilding it on a change is cheap, and an immutable
// router needs no locks on the path of every request.
type RouteTable struct {
	current atomic.Pointer[Router]
}

// NewRouteTable starts with the given router.
func NewRouteTable(r *Router) *RouteTable {
	t := &RouteTable{}
	t.current.Store(r)
	return t
}

// Swap replaces the router in force.
func (t *RouteTable) Swap(r *Router) { t.current.Store(r) }

// To returns the upstream address and whether a route was found.
func (t *RouteTable) To(host string) (string, bool) { return t.current.Load().To(host) }

// Named reports whether the host is served by a route that names it.
func (t *RouteTable) Named(host string) bool { return t.current.Load().Named(host) }

// Names lists the exact names the node serves.
func (t *RouteTable) Names() []string { return t.current.Load().Names() }
