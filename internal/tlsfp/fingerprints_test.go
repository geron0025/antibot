package tlsfp

import "testing"

func TestFingerprintsMatchReference(t *testing.T) {
	for _, r := range references(t) {
		t.Run(r.Client, func(t *testing.T) {
			h := r.parse(t)

			if got := h.JA3(); got != r.JA3 {
				t.Errorf("JA3:\n got  %s\n want %s", got, r.JA3)
			}
			if got := h.JA3Hash(); got != r.JA3Hash {
				t.Errorf("JA3Hash: %s, want %s", got, r.JA3Hash)
			}
			if got := h.JA4(); got != r.JA4 {
				t.Errorf("JA4: %s, want %s", got, r.JA4)
			}
		})
	}
}
