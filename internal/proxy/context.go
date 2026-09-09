package proxy

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/geron0025/antibot/internal/h2fp"
	"github.com/geron0025/antibot/internal/tlsfp"
)

// connKey is the key the connection capture lies under in the context. A
// private type of its own, so that nobody outside can substitute the
// value: the signals taken off a connection are grounds for a block, and
// forging them must not be possible even by accident.
type connKey struct{}

// ConnInfo is what was captured from the connection before the first
// request.
type ConnInfo struct {
	Hello   *tlsfp.Hello
	Sniffer *h2fp.Sniffer
	Peer    net.Addr

	// State is the outcome of the handshake. It is kept here because it
	// does not reach the handler otherwise: HTTP/2 is served through
	// ServeConn and HTTP/1.1 over a wrapper, and in both cases
	// http.Request.TLS stays empty.
	State *tls.ConnectionState
}

// WithConnInfo puts the capture into the connection's context. It is
// called from http.Server.ConnContext, that is, once per connection
// rather than per request.
func WithConnInfo(ctx context.Context, info *ConnInfo) context.Context {
	return context.WithValue(ctx, connKey{}, info)
}

// ConnInfoFrom fetches the capture. Its absence is an ordinary thing:
// over HTTP without TLS there is nothing to capture.
func ConnInfoFrom(ctx context.Context) *ConnInfo {
	info, _ := ctx.Value(connKey{}).(*ConnInfo)
	return info
}
