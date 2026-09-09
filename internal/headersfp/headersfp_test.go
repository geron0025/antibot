package headersfp

import (
	"net/http"
	"testing"
)

func TestFingerprintDependsOnCompositionAndOrder(t *testing.T) {
	one := Compute([]string{"Host", "User-Agent", "Accept"})
	other := Compute([]string{"Accept", "User-Agent"})

	if one.Hash == "" {
		t.Fatal("the fingerprint is empty")
	}
	if one.Hash == other.Hash {
		t.Error("a different order produced the same fingerprint")
	}
	// Host is volatile and is not part of the composition.
	if one.Names != "user-agent,accept" {
		t.Errorf("names: %q", one.Names)
	}
}

func TestCaseDoesNotMatter(t *testing.T) {
	a := Compute([]string{"User-Agent", "Accept-Encoding"})
	b := Compute([]string{"user-agent", "ACCEPT-ENCODING"})
	if a.Hash != b.Hash {
		t.Errorf("case changed the fingerprint: %q against %q", a.Names, b.Names)
	}
}

// Volatile headers are dropped on purpose: with them the same browser
// would produce a different fingerprint on different pages of the site —
// with a cookie and without, with a referer and without.
func TestVolatileHeadersDoNotMatter(t *testing.T) {
	without := Compute([]string{"User-Agent", "Accept"})
	with := Compute([]string{"User-Agent", "Cookie", "Accept", "Referer", "Content-Length"})
	if without.Hash != with.Hash {
		t.Errorf("volatile headers made it into the fingerprint: %q against %q", without.Names, with.Names)
	}
}

func TestEmptyRequestGivesEmptyFingerprint(t *testing.T) {
	f := Compute(nil)
	if f.Hash != "" || f.Names != "" {
		t.Errorf("an empty list produced a fingerprint: %+v", f)
	}
}

// For HTTP/1.1 the order cannot be recovered, so the fingerprint is
// taken from the composition. It has to be stable: Go's map iteration is
// randomized, and without sorting the same request would produce
// different fingerprints.
func TestHTTP1FingerprintIsStable(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	for _, name := range []string{"User-Agent", "Accept", "Accept-Encoding", "Connection", "Pragma"} {
		r.Header.Set(name, "value")
	}

	first := FromHTTP1Request(r).Hash
	for i := 0; i < 50; i++ {
		if got := FromHTTP1Request(r).Hash; got != first {
			t.Fatalf("the fingerprint of one and the same request changed: %q, then %q", first, got)
		}
	}
}
