// Package facts collects the signals of a single request into one struct.
//
// It is the only thing rules, the event log and the aggregator ever see.
// That is deliberate: until a signal lands here, no rule can be written
// against it and no blocked request can be explained afterwards.
package facts

import (
	"sort"
	"time"
)

// Request is everything known about a request by the time a decision is made.
type Request struct {
	Time time.Time `json:"t"`

	// Network
	IP   string `json:"ip"`
	Port int    `json:"port,omitempty"`

	// Request
	Host    string `json:"host"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Proto   string `json:"proto"`
	UA      string `json:"ua,omitempty"`
	Referer string `json:"ref,omitempty"`

	// TLS
	JA3        string `json:"ja3,omitempty"`
	JA3Hash    string `json:"ja3_hash,omitempty"`
	JA4        string `json:"ja4,omitempty"`
	SNI        string `json:"sni,omitempty"`
	ALPN       string `json:"alpn,omitempty"`
	TLSVersion string `json:"tls,omitempty"`
	GREASE     bool   `json:"grease,omitempty"`

	// HTTP/2
	H2 string `json:"h2,omitempty"`

	// Headers
	Headers     string `json:"hdrs,omitempty"`
	HeadersHash string `json:"hdrs_hash,omitempty"`

	// Conclusions drawn from the fact bases. Filled in before the rules
	// run, so that a rule can refer to them and an event can explain the
	// decision.
	Family       string `json:"family,omitempty"`
	UAMatchesJA4 bool   `json:"ua_ok"`
	NetClass     string `json:"net_class,omitempty"`
	NetOwner     string `json:"net_owner,omitempty"`
	NetCountry   string `json:"net_country,omitempty"`
	NetProtected bool   `json:"net_protected,omitempty"`
	NetAge       int    `json:"net_age,omitempty"`

	// Outcome
	Decision string `json:"decision"`
	Rule     string `json:"rule,omitempty"`

	// Shadow holds the ids of rules that matched in shadow mode. A
	// watching rule is only useful if someone reads it: without this
	// field the observation leaves no trace and there is nothing to
	// decide by.
	Shadow []string `json:"shadow,omitempty"`

	Status   int           `json:"status,omitempty"`
	Bytes    int64         `json:"bytes,omitempty"`
	Duration time.Duration `json:"dur,omitempty"`
}

// Value fetches a field by name — the way a rule condition sees it.
//
// A dedicated method rather than reflection over tags: the list of
// fields available to rules must be visible to the eye and change
// deliberately. A typo in a field name then becomes a rule parse error
// instead of a silent "this condition never matches".
func (r *Request) Value(field string) (any, bool) {
	switch field {
	case "ip":
		return r.IP, true
	case "host":
		return r.Host, true
	case "method":
		return r.Method, true
	case "path":
		return r.Path, true
	case "proto":
		return r.Proto, true
	case "ua":
		return r.UA, true
	case "referer":
		return r.Referer, true
	case "ja3":
		return r.JA3, true
	case "ja3_hash":
		return r.JA3Hash, true
	case "ja4":
		return r.JA4, true
	case "sni":
		return r.SNI, true
	case "alpn":
		return r.ALPN, true
	case "tls":
		return r.TLSVersion, true
	case "grease":
		return r.GREASE, true
	case "h2":
		return r.H2, true
	case "headers":
		return r.Headers, true
	case "headers_hash":
		return r.HeadersHash, true
	case "family":
		return r.Family, true
	case "ua_matches_ja4":
		return r.UAMatchesJA4, true
	case "network.class":
		return r.NetClass, true
	case "network.owner":
		return r.NetOwner, true
	case "network.country":
		return r.NetCountry, true
	case "network.protected":
		return r.NetProtected, true
	case "network.age":
		return r.NetAge, true
	default:
		return nil, false
	}
}

// Kind is the type of a field's value. It is needed when a rule is
// checked: a number cannot be compared against a substring, and that
// has to surface while the rule is parsed, not on the hot path, where
// the mistake would turn into "this condition never matches".
type Kind int

const (
	KindString Kind = iota
	KindBool
	KindNumber

	// KindAddr is a string, but one the cidr operator applies to. The
	// separate kind exists so that `ua cidr [...]` is rejected at parse
	// time: the condition is not syntactically wrong, it simply never
	// matches, and that has to be an error.
	KindAddr
)

func (k Kind) String() string {
	switch k {
	case KindString:
		return "string"
	case KindBool:
		return "bool"
	case KindNumber:
		return "number"
	case KindAddr:
		return "address"
	}
	return "unknown"
}

// kinds is the single list of what rules can see. Value must cover
// exactly these names and return exactly these kinds; a test watches
// over the match.
var kinds = map[string]Kind{
	"ip":                KindAddr,
	"host":              KindString,
	"method":            KindString,
	"path":              KindString,
	"proto":             KindString,
	"ua":                KindString,
	"referer":           KindString,
	"ja3":               KindString,
	"ja3_hash":          KindString,
	"ja4":               KindString,
	"sni":               KindString,
	"alpn":              KindString,
	"tls":               KindString,
	"grease":            KindBool,
	"h2":                KindString,
	"headers":           KindString,
	"headers_hash":      KindString,
	"family":            KindString,
	"ua_matches_ja4":    KindBool,
	"network.class":     KindString,
	"network.owner":     KindString,
	"network.country":   KindString,
	"network.protected": KindBool,
	"network.age":       KindNumber,
}

// FieldKind answers what kind a field is and whether it exists at all.
func FieldKind(field string) (Kind, bool) {
	k, ok := kinds[field]
	return k, ok
}

// Fields lists every name available to rules, alphabetically. Used when
// a rule is checked: an unknown name is rejected right away rather than
// some day later.
func Fields() []string {
	names := make([]string, 0, len(kinds))
	for name := range kinds {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
