package proxy

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientAddr determines the client's address.
//
// The X-Forwarded-For header is trusted only when the connection came
// from a network allowed to set it. The reason is plain: the header is
// set with one line of curl, and trusting it by default means anyone who
// wants to can call themselves anybody — and so bypass any rule based on
// an address and put somebody else's network under a block.
//
// The chain is read right to left: on the right stands whoever is closest
// to us, and each next one was added by the previous. We walk while the
// addresses are trusted; the first untrusted one is the client.
// Everything to the left of it was written by the client itself.
func ClientAddr(r *http.Request, trusted []netip.Prefix) netip.Addr {
	peer := addrFromString(r.RemoteAddr)

	if len(trusted) == 0 || !inNetworks(peer, trusted) {
		return peer
	}

	chain := chainLinks(r.Header.Values("X-Forwarded-For"))
	for i := len(chain) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(chain[i])
		if err != nil {
			// Garbage in the chain: it cannot be trusted any further,
			// because working out who wrote it is no longer possible.
			return peer
		}
		if !inNetworks(a, trusted) {
			return a
		}
	}
	return peer
}

func chainLinks(headers []string) []string {
	var out []string
	for _, h := range headers {
		for _, part := range strings.Split(h, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

func addrFromString(s string) netip.Addr {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		host = s
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

func inNetworks(a netip.Addr, networks []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, n := range networks {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

// InOwnNetworks is the same question for the node owner's allow list.
func InOwnNetworks(a netip.Addr, own []netip.Prefix) bool { return inNetworks(a, own) }
