package tlsfp

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// reference is a ClientHello captured from a live client together with
// what it must parse into. The files live in testdata; how to recapture
// them is written in testdata/README.md.
type reference struct {
	Client  string `json:"client"`
	Raw     string `json:"raw"`
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
	Hello   struct {
		LegacyVersion     uint16   `json:"legacy_version"`
		SupportedVersions []uint16 `json:"supported_versions"`
		CipherSuites      []uint16 `json:"cipher_suites"`
		Extensions        []uint16 `json:"extensions"`
		Curves            []uint16 `json:"curves"`
		PointFormats      []byte   `json:"point_formats"`
		SigAlgs           []uint16 `json:"sig_algs"`
		ALPN              []string `json:"alpn"`
		SNI               string   `json:"sni"`
		HasSNIExt         bool     `json:"has_sni_ext"`
		HasGREASE         bool     `json:"has_grease"`
	} `json:"hello"`
}

func references(t *testing.T) []reference {
	t.Helper()
	paths, err := filepath.Glob("testdata/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no references found: %v", err)
	}
	var out []reference
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		var r reference
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		out = append(out, r)
	}
	return out
}

func (r reference) parse(t *testing.T) *Hello {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(r.Raw)
	if err != nil {
		t.Fatalf("%s: raw does not decode: %v", r.Client, err)
	}
	h, err := Parse(raw)
	if err != nil {
		t.Fatalf("%s: parsing failed: %v", r.Client, err)
	}
	return h
}

func TestParsingMatchesReference(t *testing.T) {
	for _, r := range references(t) {
		t.Run(r.Client, func(t *testing.T) {
			h := r.parse(t)

			check := func(name string, got, want []uint16) {
				t.Helper()
				if !slices.Equal(got, want) {
					t.Errorf("%s:\n got  %v\n want %v", name, got, want)
				}
			}
			check("cipher_suites", h.CipherSuites, r.Hello.CipherSuites)
			check("extensions", h.Extensions, r.Hello.Extensions)
			check("curves", h.Curves, r.Hello.Curves)
			check("sig_algs", h.SigAlgs, r.Hello.SigAlgs)
			check("supported_versions", h.SupportedVersions, r.Hello.SupportedVersions)

			if h.LegacyVersion != r.Hello.LegacyVersion {
				t.Errorf("legacy_version: %d, want %d", h.LegacyVersion, r.Hello.LegacyVersion)
			}
			if !slices.Equal(h.ALPN, r.Hello.ALPN) {
				t.Errorf("alpn: %v, want %v", h.ALPN, r.Hello.ALPN)
			}
			if !slices.Equal(h.PointFormats, r.Hello.PointFormats) {
				t.Errorf("point_formats: %v, want %v", h.PointFormats, r.Hello.PointFormats)
			}
			if h.SNI != r.Hello.SNI {
				t.Errorf("sni: %q, want %q", h.SNI, r.Hello.SNI)
			}
			if h.HasSNIExt != r.Hello.HasSNIExt {
				t.Errorf("has_sni_ext: %v, want %v", h.HasSNIExt, r.Hello.HasSNIExt)
			}
			if h.HasGREASE != r.Hello.HasGREASE {
				t.Errorf("has_grease: %v, want %v", h.HasGREASE, r.Hello.HasGREASE)
			}
		})
	}
}

// The parser sits in front of crypto/tls and sees anybody's bytes.
// Truncated input is the most common kind: scanners tear the connection
// down in the middle of the handshake.
func TestTruncatedInputDoesNotPanic(t *testing.T) {
	r := references(t)[0]
	raw, err := base64.StdEncoding.DecodeString(r.Raw)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(raw); n++ {
		if _, err := Parse(raw[:n]); err == nil {
			// A short prefix is allowed not to be an error only if it
			// somehow turned out to be a complete message — and it cannot.
			t.Fatalf("a prefix of length %d parsed without an error", n)
		}
	}
}
