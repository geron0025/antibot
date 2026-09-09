// Package catalog applies the fact set: it turns "this address" into
// "this network, of this class, owned by this company".
//
// The set carries statements about the world and nothing else — no
// rules, no actions, no decisions. Applying it changes only what a
// client is called; what to do with such a client is decided by the
// owner's rule. That border is described in
// docs/ru/protocol/fact-set.md and is the reason this package has no
// way to influence a decision.
package catalog

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// FormatVersion is the set format this node understands. It is also what
// goes into the ?format= query when the manifest is fetched: the cloud
// answers with the highest format not above the requested one, so an old
// node keeps receiving what it can read.
const FormatVersion = 1

// Network is one row of the network base.
type Network struct {
	Prefix     string `json:"prefix"`
	ASN        int    `json:"asn,omitempty"`
	Owner      string `json:"owner,omitempty"`
	Country    string `json:"country,omitempty"`
	Class      string `json:"class"`
	Protected  bool   `json:"protected,omitempty"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	VerifiedAt string `json:"verified_at"`
	FirstSeen  string `json:"first_seen,omitempty"`
	Since      int    `json:"since"`
}

// Fingerprint is one row of the fingerprint base.
type Fingerprint struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Family     string `json:"family"`
	Versions   string `json:"versions,omitempty"`
	Platform   string `json:"platform,omitempty"`
	Automated  bool   `json:"automated,omitempty"`
	Headless   bool   `json:"headless,omitempty"`
	Confidence string `json:"confidence"`
	Source     string `json:"source"`
	VerifiedAt string `json:"verified_at"`
	Since      int    `json:"since"`
}

// envelope is the outer document. Unknown fields here are an error;
// unknown fields inside the records are not — see Parse.
type envelope struct {
	Format       int               `json:"format"`
	Version      int               `json:"version"`
	CreatedAt    time.Time         `json:"created_at"`
	Networks     []json.RawMessage `json:"networks"`
	Fingerprints []json.RawMessage `json:"fingerprints"`
	Counts       map[string]int    `json:"counts,omitempty"`
}

// Set is a parsed fact set, ready for lookups.
//
// Built once when a set is applied and read from many goroutines
// afterwards without a lock: nothing in it changes after construction,
// and a new set replaces the whole value.
type Set struct {
	version   int
	createdAt time.Time

	// Networks are laid out by prefix length so that the longest match
	// is found by probing from the longest length downwards. A map per
	// length beats a linear scan over eighteen thousand rows on the hot
	// path, and beats a trie in the amount of code that has to be right.
	v4     map[int]map[netip.Addr]*Network
	v6     map[int]map[netip.Addr]*Network
	v4bits []int
	v6bits []int

	fingerprints map[string]*Fingerprint

	networks  int
	protected int
}

// Version of the set. Zero means no set is applied.
func (s *Set) Version() int {
	if s == nil {
		return 0
	}
	return s.version
}

// CreatedAt is when the cloud built the set.
func (s *Set) CreatedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.createdAt
}

// Counts reports how many rows the set holds. Needed by the shrink guard
// and by the admin UI.
func (s *Set) Counts() (networks, fingerprints, protected int) {
	if s == nil {
		return 0, 0, 0
	}
	return s.networks, len(s.fingerprints), s.protected
}

// Parse reads a set and builds the lookup structures.
//
// The envelope is strict and the records are tolerant, and the asymmetry
// is deliberate: the set travels downwards, so the receiver is older
// than the sender by exactly as long as the owner postpones an update.
// A strict record would mean no field could ever be added without
// breaking every installation that was not updated today. A missing
// required field is still an error, and it discards the whole set: a
// half-applied base is a state nobody checked.
func Parse(raw []byte) (*Set, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()

	var e envelope
	if err := decoder.Decode(&e); err != nil {
		return nil, fmt.Errorf("fact set: %w", err)
	}
	if e.Format != FormatVersion {
		return nil, fmt.Errorf("fact set: format %d, and the node understands %d", e.Format, FormatVersion)
	}
	if e.Version < 1 {
		return nil, fmt.Errorf("fact set: version %d", e.Version)
	}

	s := &Set{
		version:      e.Version,
		createdAt:    e.CreatedAt,
		v4:           map[int]map[netip.Addr]*Network{},
		v6:           map[int]map[netip.Addr]*Network{},
		fingerprints: make(map[string]*Fingerprint, len(e.Fingerprints)),
	}

	for i, raw := range e.Networks {
		n, err := parseNetwork(raw)
		if err != nil {
			return nil, fmt.Errorf("fact set: networks[%d]: %w", i, err)
		}
		prefix, err := netip.ParsePrefix(n.Prefix)
		if err != nil {
			return nil, fmt.Errorf("fact set: networks[%d]: %q is not a network: %w", i, n.Prefix, err)
		}
		prefix = prefix.Masked()

		byLength := s.v6
		if prefix.Addr().Is4() {
			byLength = s.v4
		}
		bucket, ok := byLength[prefix.Bits()]
		if !ok {
			bucket = map[netip.Addr]*Network{}
			byLength[prefix.Bits()] = bucket
		}
		bucket[prefix.Addr()] = n

		s.networks++
		if n.Protected {
			s.protected++
		}
	}

	for i, raw := range e.Fingerprints {
		f, err := parseFingerprint(raw)
		if err != nil {
			return nil, fmt.Errorf("fact set: fingerprints[%d]: %w", i, err)
		}
		s.fingerprints[f.Kind+"\x00"+f.Value] = f
	}

	s.v4bits = lengthsDescending(s.v4)
	s.v6bits = lengthsDescending(s.v6)
	return s, nil
}

func lengthsDescending(m map[int]map[netip.Addr]*Network) []int {
	out := make([]int, 0, len(m))
	for bits := range m {
		out = append(out, bits)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(out)))
	return out
}

func parseNetwork(raw []byte) (*Network, error) {
	var n Network
	if err := json.Unmarshal(raw, &n); err != nil {
		return nil, err
	}
	switch {
	case n.Prefix == "":
		return nil, fmt.Errorf("no prefix")
	case n.Class == "":
		return nil, fmt.Errorf("no class")
	case n.Confidence == "":
		return nil, fmt.Errorf("no confidence")
	case n.Source == "" || n.VerifiedAt == "":
		// A catalogue that does not remember where it took a statement
		// from starts lying with confidence.
		return nil, fmt.Errorf("no source or verified_at")
	case n.Since < 1:
		return nil, fmt.Errorf("no since")
	}
	return &n, nil
}

func parseFingerprint(raw []byte) (*Fingerprint, error) {
	var f Fingerprint
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	switch {
	case f.Kind != "ja4" && f.Kind != "h2" && f.Kind != "headers":
		return nil, fmt.Errorf("kind %q", f.Kind)
	case f.Value == "":
		return nil, fmt.Errorf("no value")
	case f.Family == "":
		return nil, fmt.Errorf("no family")
	case f.Confidence == "":
		return nil, fmt.Errorf("no confidence")
	case f.Source == "" || f.VerifiedAt == "":
		return nil, fmt.Errorf("no source or verified_at")
	case f.Since < 1:
		return nil, fmt.Errorf("no since")
	}
	return &f, nil
}

// LookupNetwork finds the longest prefix covering the address.
func (s *Set) LookupNetwork(addr netip.Addr) *Network {
	if s == nil || !addr.IsValid() {
		return nil
	}
	addr = addr.Unmap()

	byLength, lengths := s.v6, s.v6bits
	if addr.Is4() {
		byLength, lengths = s.v4, s.v4bits
	}
	for _, bits := range lengths {
		prefix, err := addr.Prefix(bits)
		if err != nil {
			continue
		}
		if n, ok := byLength[bits][prefix.Addr()]; ok {
			return n
		}
	}
	return nil
}

// LookupFingerprint finds a fingerprint of the given kind by value.
func (s *Set) LookupFingerprint(kind, value string) *Fingerprint {
	if s == nil || value == "" {
		return nil
	}
	return s.fingerprints[kind+"\x00"+value]
}

// Apply fills in what the set knows about the request.
//
// It writes only the fields the fact set is allowed to write: family,
// network.* and ua_matches_ja4. It touches nothing else, and it renders
// no decision — that is the whole point of the border.
func (s *Set) Apply(r *facts.Request) {
	if s == nil || r == nil {
		return
	}

	if addr, err := netip.ParseAddr(r.IP); err == nil {
		if n := s.LookupNetwork(addr); n != nil {
			r.NetClass = n.Class
			r.NetOwner = n.Owner
			r.NetCountry = n.Country
			r.NetProtected = n.Protected
			// Age in versions, not in days: a record that arrived in the
			// last few versions has not been checked by anybody's traffic
			// yet, and a rule may require a hold — network.age > 3.
			if age := s.version - n.Since; age > 0 {
				r.NetAge = age
			}
		}
	}

	fp := s.LookupFingerprint("ja4", r.JA4)
	if fp == nil {
		fp = s.LookupFingerprint("h2", r.H2)
	}
	if fp != nil {
		r.Family = fp.Family
	}

	r.UAMatchesJA4 = agrees(fp, r.UA)
}

// agrees answers whether the client the request claims to be agrees with
// the handshake it made.
//
// The answer is "yes" whenever there are no grounds to say otherwise —
// an unknown fingerprint, an unrecognized User-Agent, or a claim of
// being a crawler. That default is not politeness: a rule is written as
// "block those whose ua_matches_ja4 is false", and a node that accuses
// everyone it does not recognize would block the whole internet the
// moment such a rule is enabled.
//
// A self-declared crawler is deliberately never a mismatch. A real
// Googlebot renders pages with a Chromium-based browser and its
// handshake looks like Chrome; calling that a lie would cost the site
// its position in search results. Verifying a crawler needs verified
// networks — network.protected and network.class — not this comparison.
func agrees(fp *Fingerprint, ua string) bool {
	if fp == nil {
		return true
	}
	claimed := UAFamily(ua)
	if claimed == FamilyUnknown || claimed == FamilyBot {
		return true
	}
	if fp.Family == "" || fp.Family == FamilyBot {
		return true
	}
	return claimed == fp.Family
}
