package tlsfp

import (
	"crypto/md5"
	"encoding/hex"
	"strconv"
	"strings"
)

// JA3 builds the fingerprint string in its original form:
//
//	version,ciphers,extensions,groups,point_formats
//
// The values are decimal, and within a field they are separated by a
// dash. GREASE is dropped from every list — otherwise the very same
// connection of the very same browser would produce a different
// fingerprint on every handshake.
//
// The version is taken from the ClientHello header rather than from
// supported_versions: that is how JA3 is defined, and the "wrongness"
// here is deliberate — a fingerprint has to match other implementations,
// or it is useless for comparison.
func (h *Hello) JA3() string {
	ciphers, _ := withoutGREASE(h.CipherSuites)
	extensions, _ := withoutGREASE(h.Extensions)
	groups, _ := withoutGREASE(h.Curves)

	formats := make([]uint16, 0, len(h.PointFormats))
	for _, b := range h.PointFormats {
		formats = append(formats, uint16(b))
	}

	var sb strings.Builder
	sb.WriteString(strconv.FormatUint(uint64(h.LegacyVersion), 10))
	for _, list := range [][]uint16{ciphers, extensions, groups, formats} {
		sb.WriteByte(',')
		sb.WriteString(joinDecimal(list, "-"))
	}
	return sb.String()
}

// JA3Hash is the MD5 of the JA3 string. The weakness of MD5 changes
// nothing here: this is an identifier for comparison and grouping, not a
// protection.
func (h *Hello) JA3Hash() string {
	sum := md5.Sum([]byte(h.JA3()))
	return hex.EncodeToString(sum[:])
}

func joinDecimal(vs []uint16, sep string) string {
	if len(vs) == 0 {
		return ""
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.FormatUint(uint64(v), 10)
	}
	return strings.Join(parts, sep)
}
