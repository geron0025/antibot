package tlsfp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
)

// JA4 builds a fingerprint in the FoxIO format:
//
//	t13d1516h2_8daaf6152771_02713d6af862
//	│││ │ │ │  └ hash of the extensions and signature algorithms
//	│││ │ │ └ first and last character of the first ALPN
//	│││ │ └ number of extensions
//	│││ └ number of ciphers
//	││└ d — a domain name was present, i — it was not
//	│└ TLS version
//	└ t — over TCP
//
// The main difference from JA3: the lists are **sorted** before hashing.
// JA3 captured the order, and the order of ciphers in Chrome has for
// some time now changed from launch to launch — a fingerprint that
// depended on it fell apart into thousands of different values for one
// and the same browser.
func (h *Hello) JA4() string {
	return fmt.Sprintf("%s_%s_%s", h.ja4a(), h.ja4b(), h.ja4c())
}

func (h *Hello) ja4a() string {
	ciphers, _ := withoutGREASE(h.CipherSuites)
	extensions, _ := withoutGREASE(h.Extensions)

	domain := "i"
	if h.HasSNIExt {
		domain = "d"
	}

	return fmt.Sprintf("t%s%s%s%s%s",
		ja4Version(h), domain,
		twoDigits(len(ciphers)), twoDigits(len(extensions)),
		alpnMark(h.ALPN))
}

func (h *Hello) ja4b() string {
	ciphers, _ := withoutGREASE(h.CipherSuites)
	slices.Sort(ciphers)
	return truncatedSHA256(inHex(ciphers))
}

func (h *Hello) ja4c() string {
	extensions, _ := withoutGREASE(h.Extensions)

	// SNI and ALPN are excluded: their values are already accounted for
	// in the first part, and on their own almost everyone has them, so
	// they help tell nobody apart.
	extensions = slices.DeleteFunc(extensions, func(v uint16) bool {
		return v == extSNI || v == extALPN
	})
	slices.Sort(extensions)

	// The signature algorithms, on the contrary, are NOT sorted: their
	// order reflects the client's preferences and tells libraries apart.
	signatures, _ := withoutGREASE(h.SigAlgs)

	s := inHex(extensions)
	if len(signatures) > 0 {
		s += "_" + inHex(signatures)
	}
	return truncatedSHA256(s)
}

// ja4Version takes the **highest** version from supported_versions, and
// the header version when the extension is absent. That is how a client
// states its ceiling: in the header TLS 1.3 is required to write 1.2 for
// the sake of old intermediaries, and that field cannot be trusted.
func ja4Version(h *Hello) string {
	versions, _ := withoutGREASE(h.SupportedVersions)

	v := h.LegacyVersion
	if len(versions) > 0 {
		v = slices.Max(versions)
	}

	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0x0001:
		return "s1"
	default:
		return "00"
	}
}

// alpnMark is the first and last character of the first offered
// protocol. No ALPN means "00".
func alpnMark(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	p := alpn[0]
	return string(p[0]) + string(p[len(p)-1])
}

func twoDigits(n int) string {
	if n > 99 {
		n = 99
	}
	return fmt.Sprintf("%02d", n)
}

func inHex(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

// truncatedSHA256 is the first 12 hex characters of SHA-256. An empty
// list gives twelve zeros rather than the hash of an empty string: the
// format says so.
func truncatedSHA256(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
