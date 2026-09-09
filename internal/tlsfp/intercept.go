package tlsfp

import (
	"bytes"
	"io"
	"net"
	"sync"
)

// Interceptor is a connection whose ClientHello is captured on the way
// through.
//
// It works like this: the first read consumes the whole first TLS record,
// parses it and **puts the bytes back into the stream**. After that
// crypto/tls reads the same message and performs the handshake as usual,
// knowing nothing about it having been read already.
//
// Putting the bytes back rather than "peeking and leaving them in the
// kernel buffer", because there is nothing to peek with in a net.Conn:
// Read takes the data away for good.
type Interceptor struct {
	net.Conn

	once sync.Once
	rest io.Reader

	mu    sync.Mutex
	hello *Hello
	err   error
}

// Intercept wraps a connection.
func Intercept(c net.Conn) *Interceptor {
	return &Interceptor{Conn: c}
}

// Hello returns the parsed ClientHello and the parse error. Before the
// first read both are nil.
//
// It is called from the request handler, that is, from a goroutine other
// than the one that read the connection — hence the mutex.
func (i *Interceptor) Hello() (*Hello, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.hello, i.err
}

func (i *Interceptor) Read(b []byte) (int, error) {
	i.once.Do(i.capture)
	if i.rest != nil {
		return i.rest.Read(b)
	}
	return i.Conn.Read(b)
}

// capture consumes the first record, parses it and prepares the stream
// for the same bytes to be read again.
func (i *Interceptor) capture() {
	record, err := readRecord(i.Conn)

	// What was read goes back into the stream in any case, even if
	// parsing failed: deciding what to do with incomprehensible bytes is
	// the business of crypto/tls, not ours. Ours is not to swallow them
	// silently.
	if len(record) > 0 {
		i.rest = io.MultiReader(bytes.NewReader(record), i.Conn)
	}
	if err != nil {
		i.store(nil, err)
		return
	}

	h, err := Parse(record)
	i.store(h, err)
}

func (i *Interceptor) store(h *Hello, err error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.hello, i.err = h, err
}

// maxRecord is the limit on the size of the first record.
//
// TLS allows 16 KiB of payload plus the header; a ClientHello with ECH
// and post-quantum keys is already approaching that limit, but a
// legitimate client cannot exceed it. The limit is mandatory: without it
// anyone can make the node allocate as much memory as they write into
// the length field.
const maxRecord = 5 + 16384

func readRecord(r io.Reader) ([]byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(header[3])<<8 | int(header[4])
	if 5+length > maxRecord {
		return header, ErrTooLong
	}

	record := make([]byte, 5+length)
	copy(record, header)
	if _, err := io.ReadFull(r, record[5:]); err != nil {
		// What was read so far is returned: those bytes have already left
		// the connection and must not be lost.
		return record[:5], err
	}
	return record, nil
}
