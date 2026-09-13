package admin

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTokensLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-tokens.json")
	tokens, err := OpenTokens(path)
	if err != nil {
		t.Fatalf("a missing file is not an error: %v", err)
	}
	now := time.Now()

	value, tok, err := tokens.Issue("ci", ScopeWrite, 30, "owner", now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value, tokenPrefix) || len(value) != len(tokenPrefix)+43 || !strings.HasPrefix(value, tok.Prefix) {
		t.Fatalf("value %q, prefix %q", value, tok.Prefix)
	}

	// The file keeps the hash, never the value, and nobody else reads it.
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), value) {
		t.Fatal("the file holds the token's value")
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}

	got, err := tokens.Check(value, now)
	if err != nil || got.Name != "ci" || !got.Allows(ScopeWrite) {
		t.Fatalf("%+v %v", got, err)
	}

	for name, issue := range map[string]func() error{
		"the same live name": func() error { _, _, err := tokens.Issue("ci", ScopeRead, 30, "owner", now); return err },
		"an unknown scope":   func() error { _, _, err := tokens.Issue("x", "admin", 30, "owner", now); return err },
		"zero days":          func() error { _, _, err := tokens.Issue("x", ScopeRead, 0, "owner", now); return err },
		"over a year":        func() error { _, _, err := tokens.Issue("x", ScopeRead, 366, "owner", now); return err },
		"a path for a name":  func() error { _, _, err := tokens.Issue("../x", ScopeRead, 30, "owner", now); return err },
	} {
		if issue() == nil {
			t.Errorf("%s was issued", name)
		}
	}

	for value, want := range map[string]error{
		"abn_nonsense":              ErrTokenUnknown,
		"ab_" + value[len("abn_"):]: ErrTokenUnknown,
		"":                          ErrTokenUnknown,
	} {
		if _, err := tokens.Check(value, now); !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", value, err, want)
		}
	}
	if _, err := tokens.Check(value, now.AddDate(0, 0, 31)); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("after its term: %v", err)
	}

	if err := tokens.Revoke("ci", now); err != nil {
		t.Fatal(err)
	}
	if _, err := tokens.Check(value, now); !errors.Is(err, ErrTokenRevoked) {
		t.Errorf("revoked: %v", err)
	}
	if err := tokens.Revoke("ci", now); err == nil {
		t.Error("a revoked token was revoked twice")
	}
	// The name is free again, and the revoked row stays in the list.
	if _, _, err := tokens.Issue("ci", ScopeRead, 30, "owner", now); err != nil {
		t.Fatal(err)
	}
	list, _ := tokens.List()
	if len(list) != 2 || list[0].State(now) != TokenRevoked {
		t.Fatalf("%+v", list)
	}
}

// The node and the command hold the same file: what one issues or
// revokes, the other sees without a restart.
func TestTokensFollowTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api-tokens.json")
	node, _ := OpenTokens(path)
	command, _ := OpenTokens(path)
	now := time.Now()

	value, _, err := command.Issue("monitoring", ScopeRead, 30, "cli:root", now)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := node.Check(value, now)
	if err != nil || tok.Allows(ScopeWrite) {
		t.Fatalf("%+v %v", tok, err)
	}

	// The use is written down, and the command keeps it when it writes.
	if err := command.Revoke("monitoring", now); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Check(value, now); !errors.Is(err, ErrTokenRevoked) {
		t.Fatalf("revoked by the command: %v", err)
	}
	list, _ := command.List()
	if list[0].UsedAt == nil {
		t.Fatal("the use was not written down")
	}
}
