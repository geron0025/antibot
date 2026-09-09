package h2fp

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

type bytesConn struct{ r *bytes.Reader }

func (c *bytesConn) Read(p []byte) (int, error)       { return c.r.Read(p) }
func (c *bytesConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *bytesConn) Close() error                     { return nil }
func (c *bytesConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (c *bytesConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (c *bytesConn) SetDeadline(time.Time) error      { return nil }
func (c *bytesConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bytesConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// The sniffer sits in the connection's read goroutine: any panic in it is
// not a spoiled fingerprint but a crashed node. A single property is
// checked, but on any input: parsing neither panics nor loops forever.
//
// The very first run against a live connection found exactly such a
// panic: the buffer was cleared inside frame parsing and advanced after
// it.
func FuzzSnifferDoesNotCrash(f *testing.F) {
	f.Add([]byte(preface))
	f.Add(append([]byte(preface), 0, 0, 6, frameSettings, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100))
	f.Add([]byte("GET / HTTP/1.1\r\n\r\n"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		s := Sniff(&bytesConn{r: bytes.NewReader(data)})
		if _, err := io.Copy(io.Discard, s); err != nil {
			t.Fatalf("reading must not break: %v", err)
		}
		// The fingerprint must render into a string in any state.
		_ = s.Fingerprint().String()
	})
}

// A stream read one byte at a time must give the same fingerprint as one
// read whole: the read boundaries are set by the network, not the client.
func TestReadBoundariesDoNotMatter(t *testing.T) {
	full := append([]byte(preface),
		0, 0, 6, frameSettings, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100)

	atOnce := Sniff(&bytesConn{r: bytes.NewReader(full)})
	io.Copy(io.Discard, atOnce)

	byByte := Sniff(&bytesConn{r: bytes.NewReader(full)})
	one := make([]byte, 1)
	for {
		if _, err := byByte.Read(one); err != nil {
			break
		}
	}

	if atOnce.Fingerprint().String() != byByte.Fingerprint().String() {
		t.Errorf("the fingerprints diverged:\n whole:   %s\n by byte: %s",
			atOnce.Fingerprint(), byByte.Fingerprint())
	}
}
