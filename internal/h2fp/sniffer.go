package h2fp

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"sync"

	"golang.org/x/net/http2/hpack"
)

// The HTTP/2 client preface — the 24 bytes a connection starts with.
const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// The frame types we care about.
const (
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameSettings     = 0x4
	frameWindowUpdate = 0x8
	frameContinuation = 0x9
)

const flagEndHeaders = 0x4
const flagAck = 0x1

// bufferLimit is how many bytes we are willing to look through before
// giving up.
//
// The fingerprint is taken from the start of the connection: the preface,
// SETTINGS and the first HEADERS fit into a few kilobytes. The limit is
// there for a client that sends anything but HEADERS — accumulation must
// not turn into a way of occupying the node's memory.
const bufferLimit = 64 << 10

// Sniffer reads the client's stream of frames along the way, without
// getting in its way.
//
// Unlike the ClientHello interception, nothing is put back into the
// stream here: the bytes are copied out of an already-read buffer, and
// Read itself works as usual. As soon as the fingerprint is taken, the
// copying stops entirely.
type Sniffer struct {
	net.Conn

	mu        sync.Mutex
	buf       []byte
	done      bool
	prefaceOK bool
	fp        Fingerprint
	decoder   *hpack.Decoder
	headers   []byte
}

func Sniff(c net.Conn) *Sniffer {
	return &Sniffer{Conn: c}
}

// Fingerprint returns what has been captured so far.
func (s *Sniffer) Fingerprint() Fingerprint {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fp
}

func (s *Sniffer) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if n > 0 {
		s.mu.Lock()
		if !s.done {
			s.buf = append(s.buf, b[:n]...)
			s.parse()
			if len(s.buf) > bufferLimit {
				s.giveUp()
			}
		}
		s.mu.Unlock()
	}
	return n, err
}

// giveUp stops the sniffer, leaving what was captured as it is.
func (s *Sniffer) giveUp() {
	s.done = true
	s.buf = nil
	s.headers = nil
	s.decoder = nil
}

// parse is called under the mutex and parses everything that has managed
// to accumulate. An incomplete frame stays in the buffer until the next
// read.
func (s *Sniffer) parse() {
	if !s.prefaceOK {
		if len(s.buf) < len(preface) {
			return
		}
		if !bytes.HasPrefix(s.buf, []byte(preface)) {
			// This is not HTTP/2. There is nothing to capture.
			s.giveUp()
			return
		}
		s.buf = s.buf[len(preface):]
		s.prefaceOK = true
	}

	for !s.done {
		if len(s.buf) < 9 {
			return
		}
		length := int(s.buf[0])<<16 | int(s.buf[1])<<8 | int(s.buf[2])
		if len(s.buf) < 9+length {
			return
		}

		kind := s.buf[3]
		flags := s.buf[4]
		stream := binary.BigEndian.Uint32(s.buf[5:9]) & 0x7fffffff
		body := s.buf[9 : 9+length]

		// The buffer is advanced BEFORE the frame is parsed, not after:
		// parsing may end the sniffer's work and clear the buffer, and
		// then advancing afterwards slices an already-nil slice. This
		// cost a panic in the read goroutine, that is, the whole node
		// crashing on the very first request.
		s.buf = s.buf[9+length:]
		s.frame(kind, flags, stream, body)
	}
}

func (s *Sniffer) frame(kind, flags byte, stream uint32, body []byte) {
	switch kind {
	case frameSettings:
		if flags&flagAck != 0 || s.fp.Settings != nil {
			return
		}
		for len(body) >= 6 {
			s.fp.Settings = append(s.fp.Settings, Setting{
				ID:    binary.BigEndian.Uint16(body[0:2]),
				Value: binary.BigEndian.Uint32(body[2:6]),
			})
			body = body[6:]
		}
		// An empty SETTINGS is legitimate, but the list must stop being
		// nil, or the next SETTINGS would be recorded as the first one.
		if s.fp.Settings == nil {
			s.fp.Settings = []Setting{}
		}

	case frameWindowUpdate:
		// We care about the connection window increment, not that of an
		// individual stream.
		if stream == 0 && s.fp.WindowUpdate == 0 && len(body) >= 4 {
			s.fp.WindowUpdate = binary.BigEndian.Uint32(body[0:4]) & 0x7fffffff
		}

	case framePriority:
		if len(body) >= 5 {
			dependency := binary.BigEndian.Uint32(body[0:4])
			s.fp.Priority = append(s.fp.Priority, Priority{
				Stream:    stream,
				Exclusive: dependency&0x80000000 != 0,
				DependsOn: dependency & 0x7fffffff,
				// In the frame the weight is stored one less than real.
				Weight: uint16(body[4]) + 1,
			})
		}

	case frameHeaders, frameContinuation:
		body = s.trimPriority(kind, flags, body)
		s.headers = append(s.headers, body...)
		if flags&flagEndHeaders != 0 {
			s.recordPseudo()
			s.fp.Complete = s.fp.Pseudo != ""
			s.giveUp()
		}
	}
}

// trimPriority strips the priority field if HEADERS carries one: it sits
// before the header block and is not part of HPACK.
func (s *Sniffer) trimPriority(kind, flags byte, body []byte) []byte {
	const flagPriority = 0x20
	if kind == frameHeaders && flags&flagPriority != 0 && len(body) >= 5 {
		return body[5:]
	}
	return body
}

// recordPseudo decodes the header block and keeps only the order of the
// pseudo-headers from it: m — method, a — authority, s — scheme,
// p — path. The values are not stored and never leave.
func (s *Sniffer) recordPseudo() {
	var order []string

	s.decoder = hpack.NewDecoder(4096, func(f hpack.HeaderField) {
		switch f.Name {
		case ":method":
			order = append(order, "m")
		case ":authority":
			order = append(order, "a")
		case ":scheme":
			order = append(order, "s")
		case ":path":
			order = append(order, "p")
		}
	})

	// A decoding error means the client sent invalid HPACK. The
	// fingerprint then stays incomplete, and that is the right outcome:
	// inventing an order out of a partially parsed block is not allowed.
	if _, err := s.decoder.Write(s.headers); err != nil {
		return
	}
	s.fp.Pseudo = strings.Join(order, ",")
}
