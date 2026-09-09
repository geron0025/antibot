package tlsfp

import "errors"

// ErrNotHello means the bytes do not look like a ClientHello: wrong
// record or wrong handshake message.
var ErrNotHello = errors.New("tlsfp: not a ClientHello")

// ErrTooLong means the client announced a record longer than TLS allows.
var ErrTooLong = errors.New("tlsfp: record longer than allowed")
