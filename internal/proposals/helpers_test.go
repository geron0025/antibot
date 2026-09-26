package proposals

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/geron0025/antibot/internal/catalog"
)

const testNodeID = "8f14e45fceea167a5a36dedd4bea2543"

// testSigner is a throwaway ed25519 key pair for signing test documents —
// the production signing key lives only on the cloud's server, and
// these tests stand in for it.
type testSigner struct {
	keyID   string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newTestSigner(t *testing.T, keyID string) *testSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testSigner{keyID: keyID, public: pub, private: priv}
}

// key describes this signer's public half the way keys.json does.
func (s *testSigner) key(use string) catalog.Key {
	return catalog.Key{KeyID: s.keyID, Algo: "ed25519", Use: use,
		Public: base64.StdEncoding.EncodeToString(s.public)}
}

// sign produces the X-Antibot-Signature header value for a body.
func (s *testSigner) sign(body []byte) string {
	sum := sha256.Sum256(body)
	return s.keyID + ":" + base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, sum[:]))
}

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 1}))
}

// goodDocument is one valid proposal and one valid advice entry, the
// same shape as the protocol's own example — a starting point the tests
// mutate one field at a time.
func goodDocument(node string) map[string]any {
	return map[string]any{
		"format":     1,
		"node":       node,
		"created_at": "2026-09-09T04:00:00Z",
		"proposals": []any{
			map[string]any{
				"id":         "cloud-hosting-no-browser-2026-09",
				"created_at": "2026-09-09T04:00:00Z",
				"expires_at": "2026-10-09T00:00:00Z",
				"rule": map[string]any{
					"id":       "cloud-hosting-no-browser-2026-09",
					"name":     "hosting without a browser handshake",
					"scope":    []any{"shop.example.ru"},
					"priority": 100,
					"condition": map[string]any{
						"all": []any{
							map[string]any{"field": "network.class", "op": "eq", "value": "hosting"},
							map[string]any{"field": "ua_matches_ja4", "op": "eq", "value": false},
						},
					},
					"action": map[string]any{"type": "block", "status": 403},
				},
				"why": "4128 requests over a week from hosting networks naming themselves Chrome.",
				"evidence": map[string]any{
					"window": "2026-09-02/2026-09-09", "requests": 4128, "share": 0.021,
					"networks": 6, "addresses": 143,
					"would_block": 4128, "would_block_protected": 0,
				},
			},
		},
		"advice": []any{
			map[string]any{
				"id":         "cloud-advice-cuts-people-2026-09",
				"created_at": "2026-09-09T04:00:00Z",
				"expires_at": "2026-09-23T00:00:00Z",
				"rule":       "50c32b7c35cdaae8",
				"suggest":    "disable",
				"why":        "3104 requests over a week, most of them carrying a cookie.",
				"evidence": map[string]any{
					"window": "2026-09-02/2026-09-09", "requests": 3104, "share": 0.016,
					"with_cookie": 2870, "protected": 0,
				},
			},
		},
	}
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// deepCopy round-trips through JSON, so a test can mutate one field of
// goodDocument() without the others seeing it.
func deepCopy(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	raw := marshal(t, doc)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
