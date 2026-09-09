package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// --- building a signed set for the tests ---

type signer struct {
	keyID   string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

func newSigner(t *testing.T, keyID string) *signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{keyID: keyID, public: pub, private: priv}
}

func (s *signer) key(use string) Key {
	return Key{KeyID: s.keyID, Algo: "ed25519", Use: use,
		Public: base64.StdEncoding.EncodeToString(s.public)}
}

// ring returns a keyring trusting this signer, the way a built-in key
// would be trusted.
func (s *signer) ring(t *testing.T, use string) *Keyring {
	t.Helper()
	r := &Keyring{keys: map[string]*Key{}}
	k := s.key(use)
	k.builtin = true
	if err := k.parse(); err != nil {
		t.Fatal(err)
	}
	r.keys[k.KeyID] = &k
	return r
}

// set builds a set document and the manifest signed for it.
func (s *signer) set(t *testing.T, version int, networks, fingerprints []any) (manifest, body []byte) {
	t.Helper()
	doc := map[string]any{
		"format":       1,
		"version":      version,
		"created_at":   "2026-09-09T04:00:00Z",
		"networks":     networks,
		"fingerprints": fingerprints,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)

	m := &Manifest{
		Version:   version,
		CreatedAt: time.Date(2026, 9, 9, 4, 0, 0, 0, time.UTC),
		Size:      int64(len(body)),
		SHA256:    hex.EncodeToString(sum[:]),
		KeyID:     s.keyID,
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(s.private, m.Digest()))

	manifest, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return manifest, body
}

func network(prefix, class string, since int, opts ...func(map[string]any)) map[string]any {
	n := map[string]any{
		"prefix": prefix, "class": class, "confidence": "verified",
		"source": "whois:RIPE", "verified_at": "2026-09-01", "since": since,
	}
	for _, o := range opts {
		o(n)
	}
	return n
}

func protectedNet() func(map[string]any) {
	return func(n map[string]any) { n["protected"] = true }
}

func owner(name string) func(map[string]any) {
	return func(n map[string]any) { n["owner"] = name }
}

func fingerprint(kind, value, family string, since int) map[string]any {
	return map[string]any{
		"kind": kind, "value": value, "family": family, "confidence": "verified",
		"source": "capture", "verified_at": "2026-09-01", "since": since,
	}
}

func store(t *testing.T, s *signer) *Store {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	st, err := Open(t.TempDir(), true, quiet)
	if err != nil {
		t.Fatal(err)
	}
	st.keys = s.ring(t, UseFacts)
	return st
}

// --- lookups ---

func TestLongestPrefixWins(t *testing.T) {
	_, body := newSigner(t, "k").set(t, 1, []any{
		network("203.0.113.0/24", "hosting", 1),
		network("203.0.0.0/8", "isp", 1, protectedNet()),
		network("2001:db8::/32", "cloud", 1),
	}, nil)

	set, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"203.0.113.7":  "hosting", // the /24 is more specific than the /8
		"203.0.114.7":  "isp",
		"198.51.100.1": "",
		"2001:db8::1":  "cloud",
	}
	for addr, want := range cases {
		n := set.LookupNetwork(netip.MustParseAddr(addr))
		got := ""
		if n != nil {
			got = n.Class
		}
		if got != want {
			t.Errorf("%s: class %q, want %q", addr, got, want)
		}
	}
}

// The set fills in exactly the fields it is allowed to fill and nothing
// else: everything the rules see beyond them comes from the request.
func TestApplyFillsOnlyItsOwnFields(t *testing.T) {
	_, body := newSigner(t, "k").set(t, 140, []any{
		network("203.0.113.0/24", "hosting", 137, owner("Example Hosting Ltd")),
	}, []any{
		fingerprint("ja4", "t13d1516h2", "chrome", 137),
	})
	set, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}

	r := facts.Request{
		IP: "203.0.113.7", Host: "shop.example.ru", Method: "GET",
		JA4: "t13d1516h2", UA: "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0 Safari/537.36",
	}
	set.Apply(&r)

	if r.NetClass != "hosting" || r.NetOwner != "Example Hosting Ltd" {
		t.Errorf("network fields: %+v", r)
	}
	if r.Family != "chrome" {
		t.Errorf("family %q", r.Family)
	}
	// age in versions: 140 − 137.
	if r.NetAge != 3 {
		t.Errorf("network.age %d, want 3", r.NetAge)
	}
	if !r.UAMatchesJA4 {
		t.Error("Chrome with a Chrome fingerprint counted as a mismatch")
	}
	// Nothing that belongs to the request itself was touched.
	if r.Host != "shop.example.ru" || r.Method != "GET" {
		t.Errorf("the set overwrote the request: %+v", r)
	}
}

// The heart of the ua_matches_ja4 field: it accuses only when there are
// grounds. A rule is written as "block those whose ua_matches_ja4 is
// false", and a node that accuses everyone it does not recognize would
// block the whole internet the moment such a rule is enabled.
func TestMismatchIsOnlyClaimedWithGrounds(t *testing.T) {
	_, body := newSigner(t, "k").set(t, 1, nil, []any{
		fingerprint("ja4", "chrome-fp", "chrome", 1),
		fingerprint("ja4", "go-fp", "go", 1),
	})
	set, err := Parse(body)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		ja4  string
		ua   string
		want bool
	}{
		{"chrome says chrome", "chrome-fp", "Mozilla/5.0 Chrome/131.0 Safari/537.36", true},
		{"Go library says Chrome", "go-fp", "Mozilla/5.0 Chrome/131.0 Safari/537.36", false},
		{"Go library says so itself", "go-fp", "Go-http-client/2.0", true},
		{"unknown fingerprint", "nobody-knows", "Mozilla/5.0 Chrome/131.0", true},
		{"no User-Agent at all", "chrome-fp", "", true},
		// A real Googlebot renders with Chromium and its handshake looks
		// like Chrome. Calling that a lie would cost the site its
		// position in search results; verifying a crawler needs verified
		// networks, not this comparison.
		{"a crawler with a browser handshake", "chrome-fp",
			"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", true},
		{"Edge is Chromium", "chrome-fp",
			"Mozilla/5.0 Chrome/131.0 Safari/537.36 Edg/131.0", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := facts.Request{JA4: c.ja4, UA: c.ua}
			set.Apply(&r)
			if r.UAMatchesJA4 != c.want {
				t.Errorf("ua_matches_ja4 = %v, want %v", r.UAMatchesJA4, c.want)
			}
		})
	}
}

// A node with no set at all works: rules referring to unknown facts
// simply do not match, and nobody is accused of anything.
func TestNoSetAccusesNobody(t *testing.T) {
	var empty *Set
	r := facts.Request{IP: "203.0.113.7", JA4: "t13d", UA: "curl/8.4"}
	empty.Apply(&r)

	if r.NetClass != "" || r.Family != "" {
		t.Errorf("an empty set filled something in: %+v", r)
	}
	if empty.Version() != 0 {
		t.Errorf("version %d", empty.Version())
	}
}

// --- the envelope is strict, the records are tolerant ---

func TestUnknownFieldInARecordIsIgnored(t *testing.T) {
	n := network("203.0.113.0/24", "hosting", 1)
	n["invented_by_the_cloud_tomorrow"] = "whatever"

	_, body := newSigner(t, "k").set(t, 1, []any{n}, nil)
	set, err := Parse(body)
	if err != nil {
		t.Fatalf("an unknown field inside a record broke the whole set: %v", err)
	}
	if set.LookupNetwork(netip.MustParseAddr("203.0.113.7")) == nil {
		t.Error("the record was lost")
	}
}

func TestUnknownFieldInTheEnvelopeIsAnError(t *testing.T) {
	body := []byte(`{"format":1,"version":1,"created_at":"2026-09-09T04:00:00Z",
		"networks":[],"fingerprints":[],"invented":"whatever"}`)
	if _, err := Parse(body); err == nil {
		t.Error("an unknown field in the envelope was accepted")
	}
}

func TestAMissingRequiredFieldDiscardsTheWholeSet(t *testing.T) {
	bad := network("203.0.113.0/24", "hosting", 1)
	delete(bad, "source") // a catalogue that forgets where it took a statement from

	_, body := newSigner(t, "k").set(t, 1, []any{
		network("198.51.100.0/24", "isp", 1),
		bad,
	}, nil)
	if _, err := Parse(body); err == nil {
		t.Error("a record without a source was accepted")
	}
}

// --- installing: the five checks in order ---

func TestInstallAndRollback(t *testing.T) {
	s := newSigner(t, "2026-a")
	st := store(t, s)

	m1, b1 := s.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
	if _, err := st.Install(m1, b1, false); err != nil {
		t.Fatal(err)
	}
	m2, b2 := s.set(t, 138, []any{
		network("203.0.113.0/24", "cloud", 138),
		network("198.51.100.0/24", "isp", 138),
	}, nil)
	if _, err := st.Install(m2, b2, false); err != nil {
		t.Fatal(err)
	}

	r := facts.Request{IP: "203.0.113.7"}
	st.Apply(&r)
	if r.NetClass != "cloud" {
		t.Fatalf("the fresh set is not in force: %q", r.NetClass)
	}

	// A rollback needs no network: it is done when something is already
	// broken.
	if _, err := st.Rollback(); err != nil {
		t.Fatal(err)
	}
	back := facts.Request{IP: "203.0.113.7"}
	st.Apply(&back)
	if back.NetClass != "hosting" {
		t.Errorf("after the rollback the class is %q, want hosting", back.NetClass)
	}
	if st.Current().Version() != 137 {
		t.Errorf("version after the rollback: %d", st.Current().Version())
	}
}

func TestInstallRefusesWhatTheProtocolSaysItMust(t *testing.T) {
	good := newSigner(t, "2026-a")
	stranger := newSigner(t, "2026-x")

	t.Run("a foreign key", func(t *testing.T) {
		st := store(t, good)
		m, b := stranger.set(t, 137, nil, nil)
		if _, err := st.Install(m, b, false); err == nil {
			t.Error("a set signed by an untrusted key was applied")
		}
	})

	t.Run("a broken signature", func(t *testing.T) {
		st := store(t, good)
		m, b := good.set(t, 137, nil, nil)
		var doc map[string]any
		json.Unmarshal(m, &doc)
		doc["signature"] = base64.StdEncoding.EncodeToString([]byte("not a signature at all!!"))
		spoiled, _ := json.Marshal(doc)
		if _, err := st.Install(spoiled, b, false); err == nil {
			t.Error("a set with a broken signature was applied")
		}
	})

	t.Run("the body swapped under the manifest", func(t *testing.T) {
		st := store(t, good)
		m, _ := good.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
		_, other := good.set(t, 137, []any{network("203.0.113.0/24", "isp", 137)}, nil)
		if _, err := st.Install(m, other, false); err == nil {
			t.Error("a set that does not match its manifest was applied")
		}
	})

	t.Run("a version going backwards", func(t *testing.T) {
		st := store(t, good)
		m2, b2 := good.set(t, 138, nil, nil)
		if _, err := st.Install(m2, b2, false); err != nil {
			t.Fatal(err)
		}
		m1, b1 := good.set(t, 137, nil, nil)
		if _, err := st.Install(m1, b1, false); err == nil {
			t.Error("an older version was applied over a newer one")
		}
	})

	t.Run("a key for the wrong channel", func(t *testing.T) {
		st := store(t, good)
		st.keys = good.ring(t, UseProposals) // signs proposals, not sets
		m, b := good.set(t, 137, nil, nil)
		if _, err := st.Install(m, b, false); err == nil {
			t.Error("a set signed by the proposals key was applied")
		}
	})
}

// A shrunken base is more dangerous than a stale one: a vanished
// "do not touch this operator" row turns a sensible rule into a block on
// live people.
func TestAShrunkenSetIsNotAppliedByItself(t *testing.T) {
	s := newSigner(t, "2026-a")
	st := store(t, s)

	var many []any
	for i := 0; i < 20; i++ {
		many = append(many, network(fmt.Sprintf("203.0.%d.0/24", i), "isp", 137, protectedNet()))
	}
	m1, b1 := s.set(t, 137, many, nil)
	if _, err := st.Install(m1, b1, false); err != nil {
		t.Fatal(err)
	}

	m2, b2 := s.set(t, 138, many[:3], nil)
	_, err := st.Install(m2, b2, false)
	if !errors.Is(err, ErrShrunk) {
		t.Fatalf("a shrunken set was applied: %v", err)
	}
	// The previous one stays in force.
	if st.Current().Version() != 137 {
		t.Errorf("version %d after the refusal", st.Current().Version())
	}
	// With an explicit confirmation it goes through: the guard is a
	// question to a human, not a wall.
	if _, err := st.Install(m2, b2, true); err != nil {
		t.Errorf("the confirmed set was not applied: %v", err)
	}
}

// Only three versions stay on disk: a rollback has to be possible, and
// somebody else's disk is not ours to fill.
func TestOnlyThreeVersionsAreKept(t *testing.T) {
	s := newSigner(t, "2026-a")
	st := store(t, s)

	for v := 130; v <= 135; v++ {
		m, b := s.set(t, v, []any{network("203.0.113.0/24", "hosting", v)}, nil)
		if _, err := st.Install(m, b, false); err != nil {
			t.Fatal(err)
		}
	}
	versions := st.Versions()
	if len(versions) != keep {
		t.Fatalf("%d versions on disk: %v", len(versions), versions)
	}
	if versions[len(versions)-1] != 135 {
		t.Errorf("the newest on disk is %d", versions[len(versions)-1])
	}
}

// The applied set survives a restart: it is read back from disk, and the
// node does not go blind because it was restarted.
func TestTheAppliedSetSurvivesARestart(t *testing.T) {
	s := newSigner(t, "2026-a")
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	dir := t.TempDir()

	first, err := Open(dir, true, quiet)
	if err != nil {
		t.Fatal(err)
	}
	first.keys = s.ring(t, UseFacts)
	m, b := s.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
	if _, err := first.Install(m, b, false); err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir, true, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if again.Current().Version() != 137 {
		t.Fatalf("after the restart version %d", again.Current().Version())
	}
	r := facts.Request{IP: "203.0.113.7"}
	again.Apply(&r)
	if r.NetClass != "hosting" {
		t.Errorf("class after the restart: %q", r.NetClass)
	}
}

// facts.enabled: false is the switch promised by the protocol. It must
// turn the whole thing off, not merely stop the fetching — a set already
// on disk would keep being applied otherwise.
func TestTheSwitchTurnsEverythingOff(t *testing.T) {
	s := newSigner(t, "2026-a")
	quiet := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	dir := t.TempDir()

	on, err := Open(dir, true, quiet)
	if err != nil {
		t.Fatal(err)
	}
	on.keys = s.ring(t, UseFacts)
	m, b := s.set(t, 137, []any{network("203.0.113.0/24", "hosting", 137)}, nil)
	if _, err := on.Install(m, b, false); err != nil {
		t.Fatal(err)
	}

	off, err := Open(dir, false, quiet)
	if err != nil {
		t.Fatal(err)
	}
	r := facts.Request{IP: "203.0.113.7"}
	off.Apply(&r)
	if r.NetClass != "" {
		t.Errorf("the switch did not turn the set off: %q", r.NetClass)
	}
	if _, err := off.Install(m, b, false); err == nil {
		t.Error("a set was applied while switched off")
	}
}

// --- keys ---

// Rotation without a release: a new key arrives signed by a key already
// trusted.
func TestANewKeyArrivesSignedByTheCurrentOne(t *testing.T) {
	current := newSigner(t, "2026-a")
	fresh := newSigner(t, "2026-b")

	ring := current.ring(t, UseFacts)
	f := keyFile{Format: 1, Keys: []Key{fresh.key(UseFacts)}, SignedBy: current.keyID}
	body := f
	body.Signature = ""
	payload, _ := json.Marshal(body)
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(current.private, payload))

	if err := ring.Add(f); err != nil {
		t.Fatalf("a properly signed key was not accepted: %v", err)
	}
	if ring.Trusted() != 2 {
		t.Errorf("%d keys in the ring", ring.Trusted())
	}

	// A set signed by the new key now verifies.
	m, b := fresh.set(t, 137, nil, nil)
	manifest, err := ParseManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := manifest.Matches(b); err != nil {
		t.Fatal(err)
	}
	if err := ring.Verify(manifest.KeyID, UseFacts, manifest.Digest(), manifest.Signature, time.Now()); err != nil {
		t.Errorf("the new key does not work: %v", err)
	}
}

func TestAKeyListMustBeSignedByATrustedKey(t *testing.T) {
	ring := newSigner(t, "2026-a").ring(t, UseFacts)
	stranger := newSigner(t, "2026-x")

	f := keyFile{Format: 1, Keys: []Key{stranger.key(UseFacts)}, SignedBy: stranger.keyID}
	body := f
	body.Signature = ""
	payload, _ := json.Marshal(body)
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(stranger.private, payload))

	if err := ring.Add(f); err == nil {
		t.Error("a key list signed by itself was accepted")
	}
}

// A built-in key cannot be redefined over the wire: that is either a
// mistake in our build or an attempt at substitution, and both need a
// human.
func TestABuiltinKeyIsNotRedefinedOverTheWire(t *testing.T) {
	current := newSigner(t, "2026-a")
	impostor := newSigner(t, "2026-a") // the same key_id, a different key

	ring := current.ring(t, UseFacts)
	f := keyFile{Format: 1, Keys: []Key{impostor.key(UseFacts)}, SignedBy: current.keyID}
	body := f
	body.Signature = ""
	payload, _ := json.Marshal(body)
	f.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(current.private, payload))

	if err := ring.Add(f); err == nil {
		t.Error("a built-in key was redefined over the wire")
	}
}

// A key that is not valid yet does not sign yet: not_before is what lets
// a rotation be spread over time.
func TestNotBeforeIsRespected(t *testing.T) {
	s := newSigner(t, "2026-b")
	ring := &Keyring{keys: map[string]*Key{}}
	k := s.key(UseFacts)
	k.NotBefore = "2026-11-01"
	if err := k.parse(); err != nil {
		t.Fatal(err)
	}
	ring.keys[k.KeyID] = &k

	m, _ := s.set(t, 137, nil, nil)
	manifest, _ := ParseManifest(m)

	early := time.Date(2026, 9, 9, 0, 0, 0, 0, time.UTC)
	if err := ring.Verify(manifest.KeyID, UseFacts, manifest.Digest(), manifest.Signature, early); err == nil {
		t.Error("a key signed before not_before")
	}
	late := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	if err := ring.Verify(manifest.KeyID, UseFacts, manifest.Digest(), manifest.Signature, late); err != nil {
		t.Errorf("the key does not work after not_before: %v", err)
	}
}

// A node that was never told whom to believe refuses everything. That is
// correct: with no trusted key nothing verifies, and the node works on
// rules that do not reference facts.
func TestAnEmptyKeyringTrustsNobody(t *testing.T) {
	if len(builtinKeys) != 0 {
		t.Skip("built-in keys have appeared, the test needs rewriting")
	}
	ring := NewKeyring()
	if ring.Trusted() != 0 {
		t.Fatalf("%d keys out of nowhere", ring.Trusted())
	}
	s := newSigner(t, "2026-a")
	m, _ := s.set(t, 137, nil, nil)
	manifest, _ := ParseManifest(m)
	if err := ring.Verify(manifest.KeyID, UseFacts, manifest.Digest(), manifest.Signature, time.Now()); err == nil {
		t.Error("an empty keyring verified a signature")
	}
}

// A missing key list is not an error: a node that was never given extra
// keys lives on the built-in ones.
func TestAMissingKeyListIsNotAnError(t *testing.T) {
	ring := NewKeyring()
	if err := ring.LoadFile(filepath.Join(t.TempDir(), "keys.json")); err != nil {
		t.Errorf("a missing key list was an error: %v", err)
	}
}
