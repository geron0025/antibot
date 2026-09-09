package catalog

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"
)

// Key uses. A key signs one channel and not the other: one key for both
// would mean that compromising the personal signature of proposals lets
// somebody forge the base for everyone at once.
const (
	UseFacts     = "facts"
	UseProposals = "proposals"
)

// Key is one trusted public key.
type Key struct {
	KeyID     string `json:"key_id"`
	Algo      string `json:"algo"`
	Public    string `json:"public"`
	Use       string `json:"use"`
	NotBefore string `json:"not_before,omitempty"`

	// builtin marks a key compiled into the binary. Such a key cannot be
	// redefined over the wire: an arriving key with the same key_id but a
	// different value is either a mistake in our build or an attempt at
	// substitution, and both need a human.
	builtin bool

	parsed ed25519.PublicKey
}

// keyFile is the contents of keys.json.
type keyFile struct {
	Format    int    `json:"format"`
	Keys      []Key  `json:"keys"`
	SignedBy  string `json:"signed_by"`
	Signature string `json:"signature"`
}

// builtinKeys are the keys compiled into the binary — the ground of
// trust. They change with a release and only with a release.
//
// Empty until the signing key exists. An empty list is not a hole: with
// no trusted key no set verifies, and a node with no set works on rules
// that do not reference facts. Refusing everything is the correct
// behaviour for a node that was never told whom to believe.
var builtinKeys = []Key{}

// Keyring is what the node believes.
type Keyring struct {
	keys map[string]*Key
}

// NewKeyring returns the ring with only the built-in keys in it.
func NewKeyring() *Keyring {
	r := &Keyring{keys: map[string]*Key{}}
	for i := range builtinKeys {
		k := builtinKeys[i]
		k.builtin = true
		if err := k.parse(); err == nil {
			r.keys[k.KeyID] = &k
		}
	}
	return r
}

func (k *Key) parse() error {
	if k.Algo != "ed25519" {
		return fmt.Errorf("key %q: algorithm %q is not supported", k.KeyID, k.Algo)
	}
	raw, err := base64.StdEncoding.DecodeString(k.Public)
	if err != nil {
		return fmt.Errorf("key %q: %w", k.KeyID, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("key %q: %d bytes instead of %d", k.KeyID, len(raw), ed25519.PublicKeySize)
	}
	k.parsed = ed25519.PublicKey(raw)
	return nil
}

// LoadFile adds the keys from keys.json.
//
// The file must be signed by a key already trusted: that is the whole
// mechanism of rotation without a release. A missing file is not an
// error — a node that was never given extra keys lives on the built-in
// ones.
func (r *Keyring) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("key list %s: %w", path, err)
	}
	if err := r.LoadBytes(raw); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// LoadBytes adds a signed key list received over the network.
func (r *Keyring) LoadBytes(raw []byte) error {
	var f keyFile
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&f); err != nil {
		return fmt.Errorf("key list: %w", err)
	}
	if f.Format != FormatVersion {
		return fmt.Errorf("key list: format %d", f.Format)
	}
	return r.Add(f)
}

// Add takes a signed key list and merges it into the ring.
func (r *Keyring) Add(f keyFile) error {
	signer, ok := r.keys[f.SignedBy]
	if !ok {
		return fmt.Errorf("key list signed by %q, which is not trusted", f.SignedBy)
	}

	// The signature covers the list without the signature itself: the
	// bytes are rebuilt here rather than taken from the file, so that a
	// reordered or reformatted file cannot carry an old signature.
	body := f
	body.Signature = ""
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(f.Signature)
	if err != nil {
		return fmt.Errorf("key list: signature does not decode: %w", err)
	}
	if !ed25519.Verify(signer.parsed, payload, sig) {
		return fmt.Errorf("key list: signature does not verify against %q", f.SignedBy)
	}

	for i := range f.Keys {
		k := f.Keys[i]
		if k.Use != UseFacts && k.Use != UseProposals {
			return fmt.Errorf("key %q: use %q", k.KeyID, k.Use)
		}
		if err := k.parse(); err != nil {
			return err
		}
		if old, ok := r.keys[k.KeyID]; ok {
			if old.builtin && old.Public != k.Public {
				// Either our build is wrong or somebody is substituting
				// keys. Both need a human, and neither is resolved by
				// preferring one of the two values.
				return fmt.Errorf("key %q arrived with a value different from the built-in one", k.KeyID)
			}
			continue
		}
		r.keys[k.KeyID] = &k
	}
	return nil
}

// Verify checks a signature over a digest, for the given use.
//
// A key of the wrong use is refused before the mathematics: that check
// is the only thing keeping the two channels apart, and doing it after
// the signature verifies would make it decorative.
func (r *Keyring) Verify(keyID, use string, digest []byte, signature string, now time.Time) error {
	k, ok := r.keys[keyID]
	if !ok {
		return fmt.Errorf("key %q is not trusted", keyID)
	}
	if k.Use != "" && k.Use != use {
		return fmt.Errorf("key %q signs %q, not %q", keyID, k.Use, use)
	}
	if k.NotBefore != "" {
		from, err := time.Parse("2006-01-02", k.NotBefore)
		if err != nil {
			return fmt.Errorf("key %q: not_before %q", keyID, k.NotBefore)
		}
		if now.Before(from) {
			return fmt.Errorf("key %q is not valid before %s", keyID, k.NotBefore)
		}
	}

	sig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("signature does not decode: %w", err)
	}
	if !ed25519.Verify(k.parsed, digest, sig) {
		return fmt.Errorf("signature does not verify against key %q", keyID)
	}
	return nil
}

// Trusted reports how many keys the ring holds. For the admin UI and
// for tests.
func (r *Keyring) Trusted() int { return len(r.keys) }

// Manifest is the signed description of a set, delivered next to it.
type Manifest struct {
	Version   int       `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	KeyID     string    `json:"key_id"`
	Signature string    `json:"signature"`
}

// ParseManifest reads a manifest. The envelope is strict here: a
// manifest is ours, small, and travels alone — an unknown field in it
// means we are reading something else entirely.
func ParseManifest(raw []byte) (*Manifest, error) {
	var m Manifest
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Version < 1 || m.SHA256 == "" || m.KeyID == "" || m.Signature == "" {
		return nil, fmt.Errorf("manifest: a required field is missing")
	}
	return &m, nil
}

// Digest is what the signature covers: the hash of the set bound to the
// version and the date. Bound on purpose — otherwise a signature could
// be moved from one set to another.
func (m *Manifest) Digest() []byte {
	h := sha256.New()
	fmt.Fprintf(h, "antibot-facts\x00%d\x00%s\x00%s",
		m.Version, m.CreatedAt.UTC().Format(time.RFC3339), m.SHA256)
	return h.Sum(nil)
}

// Matches checks that the bytes are the set the manifest describes.
func (m *Manifest) Matches(raw []byte) error {
	sum := sha256.Sum256(raw)
	got := hex.EncodeToString(sum[:])
	if got != m.SHA256 {
		return fmt.Errorf("the set does not match the manifest: sha256 %s instead of %s", got, m.SHA256)
	}
	if m.Size > 0 && int64(len(raw)) != m.Size {
		return fmt.Errorf("the set is %d bytes, and the manifest promises %d", len(raw), m.Size)
	}
	return nil
}
