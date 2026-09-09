package tlsfp

// GREASE values are what browsers mix into the lists of ciphers,
// extensions and groups so that servers do not break on the unfamiliar.
//
// For a fingerprint they are useless and harmful: the browser picks them
// at random, and the very same Chrome would produce a different JA3 on
// every handshake. So they are dropped from every list.
//
// Their mere presence, however, is a signal: browsers send GREASE,
// hand-written clients usually do not. It is kept in the separate
// HasGREASE field.
//
// The values have the form 0xNANA (RFC 8701): the high and low bytes are
// equal, and both halves of each byte are 0xA.
func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

// withoutGREASE returns a copy of the list with the GREASE values
// removed, plus a flag saying whether at least one was dropped.
func withoutGREASE(vs []uint16) ([]uint16, bool) {
	out := make([]uint16, 0, len(vs))
	var found bool
	for _, v := range vs {
		if isGREASE(v) {
			found = true
			continue
		}
		out = append(out, v)
	}
	return out, found
}
