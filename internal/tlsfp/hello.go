// Package tlsfp parses a ClientHello before the connection reaches
// crypto/tls and computes the JA3 and JA4 fingerprints from it.
//
// By hand rather than with the standard library, because there is
// nothing ready to take here: tls.ClientHelloInfo carries neither the
// list of extensions nor their order — and that is half of JA3 and the
// key part of JA4 — and Go silently drops GREASE, even though its
// presence is a signal in itself.
package tlsfp

// Record and handshake types.
const (
	recordTypeHandshake = 0x16
	handshakeTypeHello  = 0x01
)

// Numbers of the extensions that take part in a fingerprint.
const (
	extSNI               = 0x0000
	extSupportedGroups   = 0x000a
	extECPointFormats    = 0x000b
	extSigAlgs           = 0x000d
	extALPN              = 0x0010
	extSupportedVersions = 0x002b
)

// Hello is a parsed ClientHello.
//
// The lists are kept **as they arrived**, GREASE included: the order and
// the composition are the fingerprint, and deciding what to drop from
// them belongs to whoever computes a particular fingerprint, not to the
// parser. JA3 and JA4 drop GREASE differently and sort different things.
type Hello struct {
	LegacyVersion     uint16
	SupportedVersions []uint16
	CipherSuites      []uint16
	Extensions        []uint16
	Curves            []uint16
	PointFormats      []byte
	SigAlgs           []uint16
	ALPN              []string

	// SNI is the name from the server_name extension. HasSNIExt tells
	// "the extension arrived with an empty name" apart from "there was no
	// extension": for JA4 these are different cases.
	SNI       string
	HasSNIExt bool

	HasGREASE bool
}

// Parse parses a ClientHello out of a TLS record, that is, out of bytes
// starting with 0x16.
func Parse(record []byte) (*Hello, error) {
	c := &cursor{b: record}

	if c.u8() != recordTypeHandshake {
		return nil, ErrNotHello
	}
	c.u16() // record version: carries no meaning, the real one is inside
	body := c.block16()

	if body.u8() != handshakeTypeHello {
		return nil, ErrNotHello
	}
	length := int(body.u24())
	hello := &cursor{b: body.bytes(length)}
	if err := body.error(); err != nil {
		return nil, err
	}

	return parseBody(hello)
}

func parseBody(c *cursor) (*Hello, error) {
	var h Hello

	h.LegacyVersion = c.u16()
	c.bytes(32) // random
	c.block8()  // legacy_session_id
	h.CipherSuites = c.block16().listU16()
	c.block8() // legacy_compression_methods

	// There may be no extensions at all — a legitimate, if very old,
	// ClientHello. An empty remainder here is not an error.
	if c.empty() {
		if err := c.error(); err != nil {
			return nil, err
		}
		h.detectGREASE()
		return &h, nil
	}

	extensions := c.block16()
	for !extensions.empty() && extensions.error() == nil {
		kind := extensions.u16()
		body := extensions.block16()
		h.Extensions = append(h.Extensions, kind)
		h.parseExtension(kind, body)
	}

	if err := c.error(); err != nil {
		return nil, err
	}
	if err := extensions.error(); err != nil {
		return nil, err
	}

	h.detectGREASE()
	return &h, nil
}

func (h *Hello) parseExtension(kind uint16, body *cursor) {
	switch kind {
	case extSNI:
		h.HasSNIExt = true
		list := body.block16()
		for !list.empty() && list.error() == nil {
			nameType := list.u8()
			name := list.block16()
			// Type 0 is host_name. No other one has appeared over the
			// whole life of the extension, but the parser must meet an
			// unknown type silently.
			if nameType == 0 && h.SNI == "" {
				h.SNI = string(name.b)
			}
		}

	case extSupportedGroups:
		h.Curves = body.block16().listU16()

	case extECPointFormats:
		h.PointFormats = append([]byte(nil), body.block8().b...)

	case extSigAlgs:
		h.SigAlgs = body.block16().listU16()

	case extALPN:
		list := body.block16()
		for !list.empty() && list.error() == nil {
			p := list.block8()
			if len(p.b) > 0 {
				h.ALPN = append(h.ALPN, string(p.b))
			}
		}

	case extSupportedVersions:
		h.SupportedVersions = body.block8().listU16()
	}
}

// detectGREASE sets the flag by looking at every list at once.
func (h *Hello) detectGREASE() {
	for _, list := range [][]uint16{
		h.CipherSuites, h.Extensions, h.Curves, h.SupportedVersions, h.SigAlgs,
	} {
		if _, found := withoutGREASE(list); found {
			h.HasGREASE = true
			return
		}
	}
}
