// Package h2fp takes an HTTP/2 fingerprint in the Akamai format.
//
// This is what no module for somebody else's server will give you: nginx
// handles the control frames inside itself and never exposes them, and
// the order of the pseudo-headers is lost during parsing. Yet it is
// exactly those that tell browsers apart where the TLS fingerprints
// coincide.
//
// The format:
//
//	1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
//	└ SETTINGS in the order sent   │        │ └ pseudo-header order
//	                               │        └ PRIORITY frames
//	                               └ connection window increment
package h2fp

import (
	"strconv"
	"strings"
)

// Fingerprint holds the parsed signals of an HTTP/2 connection.
type Fingerprint struct {
	Settings     []Setting
	WindowUpdate uint32
	Priority     []Priority
	Pseudo       string

	// Complete says whether everything could be captured: the order of
	// the pseudo-headers arrives in HEADERS, and the connection may not
	// live that long.
	Complete bool
}

type Setting struct {
	ID    uint16
	Value uint32
}

type Priority struct {
	Stream    uint32
	Exclusive bool
	DependsOn uint32
	Weight    uint16
}

// String assembles the fingerprint into an Akamai-format string.
func (f Fingerprint) String() string {
	if len(f.Settings) == 0 && f.Pseudo == "" {
		return ""
	}

	settings := make([]string, len(f.Settings))
	for i, s := range f.Settings {
		settings[i] = strconv.FormatUint(uint64(s.ID), 10) + ":" +
			strconv.FormatUint(uint64(s.Value), 10)
	}

	window := "00"
	if f.WindowUpdate > 0 {
		window = strconv.FormatUint(uint64(f.WindowUpdate), 10)
	}

	priorities := "0"
	if len(f.Priority) > 0 {
		parts := make([]string, len(f.Priority))
		for i, p := range f.Priority {
			exclusive := "0"
			if p.Exclusive {
				exclusive = "1"
			}
			parts[i] = strconv.FormatUint(uint64(p.Stream), 10) + ":" + exclusive + ":" +
				strconv.FormatUint(uint64(p.DependsOn), 10) + ":" +
				strconv.FormatUint(uint64(p.Weight), 10)
		}
		priorities = strings.Join(parts, ",")
	}

	return strings.Join([]string{
		strings.Join(settings, ";"), window, priorities, f.Pseudo,
	}, "|")
}
