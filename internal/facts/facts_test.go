package facts

import "testing"

// The field list and the value lookup must agree: should they drift
// apart, a rule with a typo either silently never fires or fails its
// check while the field does exist.
func TestEveryFieldIsReadable(t *testing.T) {
	var r Request
	for _, field := range Fields() {
		if _, ok := r.Value(field); !ok {
			t.Errorf("field %q is listed in Fields but cannot be read", field)
		}
	}
	if _, ok := r.Value("made_up"); ok {
		t.Error("a non-existent field was read")
	}
}

// The declared kind of a field must match what Value returns. Should
// they drift apart, a rule passes its check and silently never fires:
// comparing a string against a number is never true.
func TestKindsMatchValues(t *testing.T) {
	// The struct is deliberately filled with non-zero values: an empty
	// string and a zero number show their kind too, but checking against
	// real ones is what we want.
	r := Request{
		IP: "203.0.113.7", Host: "example.ru", Method: "GET", Path: "/",
		Proto: "HTTP/2.0", UA: "curl", Referer: "https://example.ru/",
		JA3: "ja3", JA3Hash: "hash", JA4: "t13d", SNI: "example.ru",
		ALPN: "h2", TLSVersion: "1.3", GREASE: true, H2: "h2fp",
		Headers: "host,ua", HeadersHash: "hash", Cookie: true, Family: "chrome",
		UAMatchesJA4: true, NetClass: "hosting", NetOwner: "Hetzner",
		NetCountry: "DE", NetProtected: true, NetAge: 42,
	}

	for _, field := range Fields() {
		kind, ok := FieldKind(field)
		if !ok {
			t.Errorf("field %q is in Fields but has no kind", field)
			continue
		}
		value, _ := r.Value(field)

		var matched bool
		switch value.(type) {
		case string:
			matched = kind == KindString || kind == KindAddr
		case bool:
			matched = kind == KindBool
		case int:
			matched = kind == KindNumber
		}
		if !matched {
			t.Errorf("field %q is declared as %s, but Value returned %T", field, kind, value)
		}
	}

	if _, ok := FieldKind("made_up"); ok {
		t.Error("a non-existent field turned out to have a kind")
	}
}
