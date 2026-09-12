package aggregate

import (
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/geron0025/antibot/internal/catalog"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

const (
	// WindowLength is fixed by the protocol: short enough for a
	// two-minute raid to stand out as a row of its own, long enough not
	// to multiply the volume for precision nobody uses.
	WindowLength = 5 * time.Minute

	// MaxRows is the limit on rows in one window — and, by the schema,
	// in one batch.
	MaxRows = 5000

	// liveLimit caps the distinct keys a window holds while it is open.
	// MaxRows alone limits what is sent, not what is kept: under a
	// distributed attack the keys grow as the number of addresses, and
	// the memory of the node would grow with them. Past the limit new
	// keys go straight into the ~rest row — the scale of what is
	// happening survives, the breakdown does not.
	liveLimit = 4 * MaxRows

	// rest marks the row the smallest ones are folded into.
	rest = "~rest"

	// maxRuleID and maxShadow bound what rule ids add to a row. An id is
	// the owner's free text, and the rules engine does not limit it.
	maxRuleID = 64
	maxShadow = 16
)

// Key is what rows are grouped by. The field names are the protocol's.
type Key struct {
	Domain       string `json:"domain"`
	JA4          string `json:"ja4"`
	H2           string `json:"h2"`
	Headers      string `json:"headers"`
	UAFamily     string `json:"ua_family"`
	UAMatchesJA4 bool   `json:"ua_matches_ja4"`
	Net          string `json:"net"`

	// Rule is the id of the rule that decided, empty when none did;
	// Shadow is the rules that matched in shadow mode. Both are in the
	// key rather than counted beside it: every request of a row was then
	// decided the same way, and what the row says about a rule — the
	// cookies, the paths, the answers — is exact rather than a share of
	// a mix.
	Rule   string  `json:"rule"`
	Shadow ruleIDs `json:"shadow"`
}

// restKey is the key of the folded row. The window stays a date and
// ua_matches_ja4 stays a boolean, because the schema says so; true is
// the same "no grounds to call it a liar" the node defaults to.
var restKey = Key{
	Domain: rest, JA4: rest, H2: rest, Headers: rest,
	UAFamily: rest, UAMatchesJA4: true, Net: rest,
	Rule: rest, Shadow: rest,
}

func (k Key) less(o Key) bool {
	switch {
	case k.Domain != o.Domain:
		return k.Domain < o.Domain
	case k.JA4 != o.JA4:
		return k.JA4 < o.JA4
	case k.H2 != o.H2:
		return k.H2 < o.H2
	case k.Headers != o.Headers:
		return k.Headers < o.Headers
	case k.UAFamily != o.UAFamily:
		return k.UAFamily < o.UAFamily
	case k.UAMatchesJA4 != o.UAMatchesJA4:
		return !k.UAMatchesJA4
	case k.Net != o.Net:
		return k.Net < o.Net
	case k.Rule != o.Rule:
		return k.Rule < o.Rule
	}
	return k.Shadow < o.Shadow
}

// Row is one line of the aggregate as it goes over the wire.
//
// Status and Methods are always objects, never null: the schema wants
// an object, and a nil map would turn into null.
type Row struct {
	Window string `json:"window"`
	Key
	Requests   uint64            `json:"requests"`
	WithCookie uint64            `json:"with_cookie"`
	Blocked    uint64            `json:"blocked"`
	Shadowed   uint64            `json:"shadowed"`
	Limited    uint64            `json:"limited"`
	Status     map[string]uint64 `json:"status"`
	UniqPaths  uint64            `json:"uniq_paths"`
	UniqAddrs  uint64            `json:"uniq_addrs"`
	Methods    map[string]uint64 `json:"methods"`
	BytesOut   uint64            `json:"bytes_out"`
}

// keyOf takes the key off a request. Everything that is not the key
// stays behind: no address, no User-Agent string, no path, no header
// values. This function is where the list of what is never sent is
// kept, and it keeps it by not looking.
func keyOf(r *facts.Request, served func(string) bool) Key {
	return Key{
		Domain:       domainOf(r.Host, served),
		JA4:          clip(r.JA4, 128),
		H2:           clip(r.H2, 256),
		Headers:      clip(r.HeadersHash, 64),
		UAFamily:     catalog.UAFamily(r.UA),
		UAMatchesJA4: r.UAMatchesJA4,
		Net:          prefixOf(r.IP),
		Rule:         ruleID(r.Rule),
		Shadow:       makeRuleIDs(r.Shadow),
	}
}

// domainOf returns the protected domain, or an empty string when the
// request was not to one.
//
// Host comes from the client. A scanner sends whatever it likes there,
// and a node with a default route would otherwise carry it to the cloud
// — an unbounded set of junk names, and one too long for the schema
// would get the whole batch rejected. Only a name the node serves, and
// one that looks like a name, goes out. An address in Host is not a
// domain either: it is the address of this very server.
func domainOf(host string, served func(string) bool) string {
	if host == "" || len(host) > 253 {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	for i := 0; i < len(host); i++ {
		c := host[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_') {
			return ""
		}
	}
	if served != nil && !served(host) {
		return ""
	}
	return host
}

// prefixOf cuts the address down to /24 or /48. An IPv6 client gets
// /48 rather than /64: providers hand out /64s in bulk from a shared
// /48, and by /64 one client would scatter into thousands of rows.
func prefixOf(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	addr = addr.Unmap()
	bits := 48
	if addr.Is4() {
		bits = 24
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ruleID makes a rule id fit the wire: valid UTF-8, no control
// characters, at most maxRuleID characters. The id is the owner's text
// and may be anything; the batch it would break is everybody's.
func ruleID(s string) string {
	s = strings.ToValidUTF8(s, "")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > maxRuleID {
		s = string([]rune(s)[:maxRuleID])
	}
	return s
}

// ruleIDs is a set of rule ids, sorted and kept as one string so that a
// Key stays comparable and can key a map. On the wire, and in the saved
// state, it is an array.
type ruleIDs string

// idSep cannot occur inside an id: ruleID removes control characters.
const idSep = "\n"

func makeRuleIDs(ids []string) ruleIDs {
	if len(ids) == 0 {
		return ""
	}
	clean := make([]string, 0, len(ids))
	for _, id := range ids {
		clean = append(clean, ruleID(id))
	}
	sort.Strings(clean)
	clean = slices.Compact(clean)
	if len(clean) > maxShadow {
		clean = clean[:maxShadow]
	}
	return ruleIDs(strings.Join(clean, idSep))
}

// list is never nil: the schema wants an array, and a nil slice would
// turn into null.
func (s ruleIDs) list() []string {
	if s == "" {
		return []string{}
	}
	return strings.Split(string(s), idSep)
}

func (s ruleIDs) MarshalJSON() ([]byte, error) { return json.Marshal(s.list()) }

func (s *ruleIDs) UnmarshalJSON(raw []byte) error {
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		return err
	}
	*s = ruleIDs(strings.Join(list, idSep))
	return nil
}

// methods are counted by name; anything else is OTHER. The method is
// the client's string, and without a list a single row could carry a
// thousand made-up verbs.
var methods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "DELETE": true,
	"PATCH": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

func methodOf(m string) string {
	if methods[m] {
		return m
	}
	return "OTHER"
}

func statusClass(status int) string {
	if status < 100 || status > 599 {
		return ""
	}
	return string(rune('0'+status/100)) + "xx"
}

// counts accumulates one row while its window is open.
type counts struct {
	Requests   uint64            `json:"requests"`
	WithCookie uint64            `json:"with_cookie,omitempty"`
	Blocked    uint64            `json:"blocked,omitempty"`
	Shadowed   uint64            `json:"shadowed,omitempty"`
	Limited    uint64            `json:"limited,omitempty"`
	Status     map[string]uint64 `json:"status,omitempty"`
	Methods    map[string]uint64 `json:"methods,omitempty"`
	BytesOut   uint64            `json:"bytes_out,omitempty"`
	Paths      sketch            `json:"paths"`
	Addrs      sketch            `json:"addrs"`
}

func (c *counts) add(r *facts.Request) {
	c.Requests++
	if r.Cookie {
		c.WithCookie++
	}
	switch r.Decision {
	case proxy.ActionBlock:
		c.Blocked++
	case proxy.ActionRatelimit:
		c.Limited++
	}
	if len(r.Shadow) > 0 {
		c.Shadowed++
	}
	if class := statusClass(r.Status); class != "" {
		bump(&c.Status, class, 1)
	}
	bump(&c.Methods, methodOf(r.Method), 1)
	if r.Bytes > 0 {
		c.BytesOut += uint64(r.Bytes)
	}
	// The path and the address are hashed here and never kept as they
	// are. The hashes stay on this disk; only the estimate leaves.
	if r.Path != "" {
		c.Paths.add(hash(r.Path))
	}
	if r.IP != "" {
		c.Addrs.add(hash(r.IP))
	}
}

func (c *counts) merge(o *counts) {
	c.Requests += o.Requests
	c.WithCookie += o.WithCookie
	c.Blocked += o.Blocked
	c.Shadowed += o.Shadowed
	c.Limited += o.Limited
	c.BytesOut += o.BytesOut
	for k, v := range o.Status {
		bump(&c.Status, k, v)
	}
	for k, v := range o.Methods {
		bump(&c.Methods, k, v)
	}
	c.Paths.merge(&o.Paths)
	c.Addrs.merge(&o.Addrs)
}

func (c *counts) row(start time.Time, k Key) Row {
	return Row{
		Window:     start.UTC().Format(time.RFC3339),
		Key:        k,
		Requests:   c.Requests,
		WithCookie: c.WithCookie,
		Blocked:    c.Blocked,
		Shadowed:   c.Shadowed,
		Limited:    c.Limited,
		Status:     copyMap(c.Status),
		UniqPaths:  c.Paths.estimate(),
		UniqAddrs:  c.Addrs.estimate(),
		Methods:    copyMap(c.Methods),
		BytesOut:   c.BytesOut,
	}
}

func bump(m *map[string]uint64, k string, v uint64) {
	if *m == nil {
		*m = make(map[string]uint64)
	}
	(*m)[k] += v
}

func copyMap(m map[string]uint64) map[string]uint64 {
	out := make(map[string]uint64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// window is one open five-minute window.
type window struct {
	start time.Time
	rows  map[Key]*counts

	// overflow holds the keys that arrived past liveLimit. It becomes
	// part of the ~rest row when the window closes.
	overflow *counts
}

func newWindow(start time.Time) *window {
	return &window{start: start, rows: make(map[Key]*counts)}
}

func (w *window) add(k Key, r *facts.Request) {
	c, ok := w.rows[k]
	if !ok {
		if len(w.rows) >= liveLimit {
			if w.overflow == nil {
				w.overflow = &counts{}
			}
			w.overflow.add(r)
			return
		}
		c = &counts{}
		w.rows[k] = c
	}
	c.add(r)
}

// close turns the window into rows of the aggregate: the largest first,
// and past MaxRows the smallest folded into one ~rest row with the sum
// of their counters. The folded row keeps the scale and loses the
// breakdown — exactly the trade the protocol makes.
func (w *window) close() []Row {
	type entry struct {
		key Key
		c   *counts
	}
	entries := make([]entry, 0, len(w.rows))
	for k, c := range w.rows {
		entries = append(entries, entry{k, c})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].c.Requests != entries[j].c.Requests {
			return entries[i].c.Requests > entries[j].c.Requests
		}
		return entries[i].key.less(entries[j].key)
	})

	folded := w.overflow
	keep := len(entries)
	if keep > MaxRows || (keep == MaxRows && folded != nil) {
		keep = MaxRows - 1
	}
	if keep < len(entries) {
		if folded == nil {
			folded = &counts{}
		}
		for _, e := range entries[keep:] {
			folded.merge(e.c)
		}
	}

	rows := make([]Row, 0, keep+1)
	for _, e := range entries[:keep] {
		rows = append(rows, e.c.row(w.start, e.key))
	}
	if folded != nil {
		rows = append(rows, folded.row(w.start, restKey))
	}
	return rows
}
