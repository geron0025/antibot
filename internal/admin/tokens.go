package admin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// API tokens let a program — a monitoring system, a panel of the owner's
// own, a CI job that rolls the rules out together with the site — reach
// the node's API.
//
// A token belongs to the owner of the node: it is issued only on the node,
// with `antibot-admin api-token` or on the admin UI's page, and it never leaves
// for the cloud. The node has no code that would send one, and a token
// handed to the cloud would let the cloud switch rules on at somebody's
// site — the one thing it must never be able to do.
//
// The file holds hashes, not values. A value is shown once, when it is
// issued, and a stolen copy of the file lets nobody in. SHA-256 rather
// than PBKDF2: a token is 256 random bits, and slowing down the guessing
// of something that cannot be guessed only slows down every request.

// Token scopes. Split so that a monitoring token cannot switch the
// protection off.
const (
	ScopeRead  = "read"
	ScopeWrite = "write"
)

// TokensFormatVersion is the format version of the tokens file.
const TokensFormatVersion = 1

// MaxTokenDays bounds a token's life. A token that never expires is the
// case where "for now" lasts years; a year is enough for anything that is
// still looked after.
const MaxTokenDays = 365

// tokenPrefix tells a node API token from a cloud subscription token at a
// glance — in a config, in a log, in a paste that leaked.
const tokenPrefix = "abn_"

// usedEvery is how often the last use is written down. Monitoring would
// otherwise rewrite the file several times a second, and the question the
// field answers — is anything still using this token — needs minutes.
const usedEvery = 10 * time.Minute

// Why a token was refused. The client gets 401 for all three; the log
// tells them apart.
var (
	ErrTokenUnknown = errors.New("the API token is unknown")
	ErrTokenRevoked = errors.New("the API token was revoked")
	ErrTokenExpired = errors.New("the API token has expired")
)

var tokenNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// Token states.
const (
	TokenLive    = "live"
	TokenExpired = "expired"
	TokenRevoked = "revoked"
)

// Token is an issued token as the file keeps it.
type Token struct {
	// Name is what the node's log calls the token: "who changed the rule"
	// has the answer "the token ci", not "somebody with a token".
	Name string `json:"name"`

	// Prefix is the start of the value, for recognising a token in a
	// config without the file holding the value itself.
	Prefix string `json:"prefix"`
	Hash   string `json:"hash"`
	Scope  string `json:"scope"`

	CreatedAt time.Time  `json:"created_at"`
	CreatedBy string     `json:"created_by"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// State is live, expired or revoked.
func (t *Token) State(now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return TokenRevoked
	case !now.Before(t.ExpiresAt):
		return TokenExpired
	}
	return TokenLive
}

// Allows answers whether the token may do what the scope names. Writing
// includes reading: a CI job that adds a rule also wants to see it.
func (t *Token) Allows(scope string) bool {
	return scope == ScopeRead || t.Scope == ScopeWrite
}

// Tokens are the API's tokens, a file on disk next to the accounts.
//
// The file is reread when it changes: a token issued with the command
// while the node runs works without a restart, and a revoked one stops
// working the same way. The node and the command both reread before they
// write, so neither undoes the other's change.
type Tokens struct {
	path string

	mu      sync.Mutex
	list    []Token
	modTime time.Time
	size    int64
}

type tokensFile struct {
	Version int     `json:"version"`
	Tokens  []Token `json:"tokens"`
}

// OpenTokens reads the tokens file. A missing file is not an error: no
// token has been issued yet, and the API lets nobody in.
func OpenTokens(path string) (*Tokens, error) {
	t := &Tokens{path: path}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reloadLocked(); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tokens) reloadLocked() error {
	info, err := os.Stat(t.path)
	if errors.Is(err, fs.ErrNotExist) {
		t.list, t.modTime, t.size = nil, time.Time{}, 0
		return nil
	}
	if err != nil {
		return fmt.Errorf("API tokens %s: %w", t.path, err)
	}
	if !t.modTime.IsZero() && info.ModTime().Equal(t.modTime) && info.Size() == t.size {
		return nil
	}

	contents, err := os.ReadFile(t.path)
	if err != nil {
		return fmt.Errorf("API tokens %s: %w", t.path, err)
	}
	var f tokensFile
	if err := json.Unmarshal(contents, &f); err != nil {
		return fmt.Errorf("API tokens %s: %w", t.path, err)
	}
	if f.Version != TokensFormatVersion {
		return fmt.Errorf("API tokens %s: version %d, and the node understands %d",
			t.path, f.Version, TokensFormatVersion)
	}
	t.list, t.modTime, t.size = f.Tokens, info.ModTime(), info.Size()
	return nil
}

// List returns the tokens, revoked and expired included: "what was this
// token and who issued it" must have an answer after it stopped working.
func (t *Tokens) List() ([]Token, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reloadLocked(); err != nil {
		return nil, err
	}
	out := make([]Token, len(t.list))
	copy(out, t.list)
	return out, nil
}

// Issue creates a token and returns its value — the only moment the value
// exists anywhere but in the program that will use it.
func (t *Tokens) Issue(name, scope string, days int, by string, now time.Time) (string, *Token, error) {
	if !tokenNameRe.MatchString(name) {
		return "", nil, fmt.Errorf("token name %q: letters, digits, dot, dash and underscore, up to 64", name)
	}
	if scope != ScopeRead && scope != ScopeWrite {
		return "", nil, fmt.Errorf("scope %q: it is %s or %s", scope, ScopeRead, ScopeWrite)
	}
	if days < 1 || days > MaxTokenDays {
		return "", nil, fmt.Errorf("a token lives from 1 to %d days, not %d", MaxTokenDays, days)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	value := tokenPrefix + base64.RawURLEncoding.EncodeToString(raw)

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reloadLocked(); err != nil {
		return "", nil, err
	}
	for _, existing := range t.list {
		if existing.Name == name && existing.State(now) == TokenLive {
			return "", nil, fmt.Errorf("a live token %q already exists: the name is what the log calls it", name)
		}
	}

	issued := now.UTC().Truncate(time.Second)
	tok := Token{
		Name: name, Prefix: value[:len(tokenPrefix)+6], Hash: hashToken(value), Scope: scope,
		CreatedAt: issued, CreatedBy: by, ExpiresAt: issued.AddDate(0, 0, days),
	}
	list := append(append([]Token(nil), t.list...), tok)
	if err := t.writeLocked(list); err != nil {
		return "", nil, err
	}
	return value, &tok, nil
}

// Revoke stops a live token at once. The row stays, marked: "which token
// did the CI use until the 12th" must have an answer.
func (t *Tokens) Revoke(name string, now time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reloadLocked(); err != nil {
		return err
	}
	list := append([]Token(nil), t.list...)
	found := false
	for i := range list {
		if list[i].Name == name && list[i].State(now) == TokenLive {
			at := now.UTC().Truncate(time.Second)
			list[i].RevokedAt = &at
			found = true
		}
	}
	if !found {
		return fmt.Errorf("there is no live token %q", name)
	}
	return t.writeLocked(list)
}

// Check finds the token a request presents.
func (t *Tokens) Check(value string, now time.Time) (*Token, error) {
	if !strings.HasPrefix(value, tokenPrefix) {
		return nil, ErrTokenUnknown
	}
	want := []byte(hashToken(value))

	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.reloadLocked(); err != nil {
		return nil, err
	}

	found := -1
	for i := range t.list {
		// In constant time, as a password is compared: the time of the
		// answer must not tell how much of a hash matched.
		if subtle.ConstantTimeCompare([]byte(t.list[i].Hash), want) == 1 {
			found = i
		}
	}
	if found < 0 {
		return nil, ErrTokenUnknown
	}
	tok := t.list[found]
	switch tok.State(now) {
	case TokenRevoked:
		return nil, ErrTokenRevoked
	case TokenExpired:
		return nil, ErrTokenExpired
	}

	if tok.UsedAt == nil || now.Sub(*tok.UsedAt) >= usedEvery {
		at := now.UTC().Truncate(time.Second)
		list := append([]Token(nil), t.list...)
		list[found].UsedAt = &at
		// Not recording the use is no reason to refuse the request: the
		// field is a hint for the owner, not a condition. Kept in memory
		// all the same, so that a read-only disk is not retried on every
		// request.
		if err := t.writeLocked(list); err != nil {
			t.list[found].UsedAt = &at
		}
		tok.UsedAt = &at
	}
	return &tok, nil
}

// writeLocked puts the file down atomically and with mode 0600, like the
// accounts: it is nobody else's to read.
func (t *Tokens) writeLocked(list []Token) error {
	contents, err := json.MarshalIndent(tokensFile{Version: TokensFormatVersion, Tokens: list}, "", "  ")
	if err != nil {
		return err
	}
	contents = append(contents, '\n')

	dir := filepath.Dir(t.path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".api-tokens-*.json")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o600); err != nil {
		return err
	}
	if err := os.Rename(name, t.path); err != nil {
		return err
	}

	info, err := os.Stat(t.path)
	if err != nil {
		return err
	}
	t.list, t.modTime, t.size = list, info.ModTime(), info.Size()
	return nil
}

func hashToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
