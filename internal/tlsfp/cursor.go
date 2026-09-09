package tlsfp

import "errors"

// ErrTruncated means the data ran out: the ClientHello ended earlier
// than its own length fields promised.
var ErrTruncated = errors.New("tlsfp: message truncated")

// cursor reads fields out of a byte slice while remembering one thing:
// the lengths inside a ClientHello came from outside and cannot be
// trusted.
//
// Every read checks the remainder, so parsing never panics on any input.
// This is not pedantry: the parser sits in front of crypto/tls and
// processes anybody's bytes, including those of someone who sent them on
// purpose.
type cursor struct {
	b   []byte
	err error
}

func (c *cursor) error() error { return c.err }

func (c *cursor) fail() {
	if c.err == nil {
		c.err = ErrTruncated
	}
}

// bytes returns the next n bytes.
func (c *cursor) bytes(n int) []byte {
	if c.err != nil {
		return nil
	}
	if n < 0 || len(c.b) < n {
		c.fail()
		return nil
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out
}

func (c *cursor) u8() uint8 {
	b := c.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (c *cursor) u16() uint16 {
	b := c.bytes(2)
	if b == nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

func (c *cursor) u24() uint32 {
	b := c.bytes(3)
	if b == nil {
		return 0
	}
	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2])
}

// block8 reads a block whose length is written in one byte and returns a
// cursor over its contents — that way a nested structure cannot escape
// its own bounds even if the inner lengths lie.
func (c *cursor) block8() *cursor {
	n := int(c.u8())
	return &cursor{b: c.bytes(n)}
}

// block16 is the same for a block with a two-byte length.
func (c *cursor) block16() *cursor {
	n := int(c.u16())
	return &cursor{b: c.bytes(n)}
}

func (c *cursor) empty() bool { return len(c.b) == 0 }

// listU16 reads the rest of the cursor as a sequence of uint16.
func (c *cursor) listU16() []uint16 {
	if c.err != nil {
		return nil
	}
	if len(c.b)%2 != 0 {
		c.fail()
		return nil
	}
	out := make([]uint16, 0, len(c.b)/2)
	for !c.empty() && c.err == nil {
		out = append(out, c.u16())
	}
	return out
}
