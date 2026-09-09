package tlsfp

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// A differential fuzzer: our own parser against crypto/tls.
//
// The point is that there are six references while the internet holds
// endlessly many clients, and checking a binary-format parser only
// against six known messages means checking it on what already works.
// Here the standard library acts as the second opinion: it parses the
// same ClientHello with its own code, written by other people.
//
// What counts as a divergence:
//
//   - crypto/tls parsed the message and we refused;
//   - both parsed it but disagreed on SNI, ALPN, versions, ciphers or groups.
//
// The opposite does NOT count as a divergence: we parse more leniently on
// purpose. The standard library may reject a ClientHello for reasons that
// have nothing to do with a fingerprint — an unknown compression method,
// a repeated extension, an unsupported version. Such a connection will
// not happen anyway, but we must still take a fingerprint from it and
// write it into an event: that is what half of the interesting traffic
// looks like.

// bytesConn serves bytes as a connection. No goroutines and no net.Pipe:
// the fuzzer has millions of runs ahead of it, and every blocked channel
// would turn into a hung test.
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

// stdlibOpinion is what crypto/tls read out of the ClientHello.
type stdlibOpinion struct {
	parsed   bool
	sni      string
	alpn     []string
	ciphers  []uint16
	versions []uint16
	groups   []uint16
}

var enough = errors.New("that is enough, no handshake needed beyond this point")

func askStdlib(data []byte) stdlibOpinion {
	var o stdlibOpinion

	cfg := &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			// The fields are copied: after the callback returns the
			// standard library is free to reuse its buffers.
			o.parsed = true
			o.sni = chi.ServerName
			o.alpn = slices.Clone(chi.SupportedProtos)
			o.ciphers = slices.Clone(chi.CipherSuites)
			o.versions = slices.Clone(chi.SupportedVersions)
			o.groups = make([]uint16, 0, len(chi.SupportedCurves))
			for _, g := range chi.SupportedCurves {
				o.groups = append(o.groups, uint16(g))
			}
			return nil, enough
		},
	}

	conn := &bytesConn{r: bytes.NewReader(data)}
	_ = tls.Server(conn, cfg).Handshake()
	return o
}

// compareLists compares two lists after reducing both to a GREASE-free
// form: the standard library drops GREASE silently, and comparing raw
// lists would mean catching that divergence on every browser.
func compareLists(t *testing.T, name string, ours, theirs []uint16) {
	t.Helper()
	a, _ := withoutGREASE(ours)
	b, _ := withoutGREASE(theirs)
	if !slices.Equal(a, b) {
		t.Errorf("%s diverged:\n ours:   %v\n theirs: %v", name, a, b)
	}
}

func FuzzParseAgainstStdlib(f *testing.F) {
	paths, _ := filepath.Glob("testdata/*.json")
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var r reference
		if err := json.Unmarshal(b, &r); err != nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(r.Raw)
		if err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, ourErr := Parse(data)
		theirs := askStdlib(data)

		if theirs.parsed && ourErr != nil {
			t.Fatalf("crypto/tls parsed the ClientHello and we refused: %v", ourErr)
		}
		if !theirs.parsed || ourErr != nil {
			return
		}

		if h.SNI != theirs.sni {
			t.Errorf("SNI diverged: ours %q, theirs %q", h.SNI, theirs.sni)
		}
		if !slices.Equal(h.ALPN, theirs.alpn) {
			t.Errorf("ALPN diverged: ours %v, theirs %v", h.ALPN, theirs.alpn)
		}
		compareLists(t, "ciphers", h.CipherSuites, theirs.ciphers)
		compareLists(t, "groups", h.Curves, theirs.groups)

		// The standard library returns versions sorted descending, while
		// we return them in the client's order. The comparison is by set.
		//
		// GREASE is stripped from both sides, and that is not symmetry
		// for beauty's sake: in supported_versions crypto/tls does NOT
		// drop it, even though it drops it from ciphers and groups. The
		// very first fuzzer run stumbled on exactly this.
		ourVersions, _ := withoutGREASE(h.SupportedVersions)
		theirVersions, _ := withoutGREASE(theirs.versions)
		slices.Sort(ourVersions)
		slices.Sort(theirVersions)
		if len(ourVersions) > 0 && !slices.Equal(ourVersions, theirVersions) {
			t.Errorf("versions diverged: ours %v, theirs %v", ourVersions, theirVersions)
		}

		// The fingerprints must be computable on any accepted message and
		// must not panic: this is hot-path code.
		_ = h.JA3()
		_ = h.JA4()
		_ = io.Discard
	})
}
