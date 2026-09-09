package nodeid

import (
	"os"
	"path/filepath"
	"testing"
)

// The identifier is created once and survives a restart: one regenerated
// on every start would make a single installation look like a new one
// every time, and the far side would count nodes that never existed.
func TestCreatedOnceAndKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.id")

	first, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !valid.MatchString(first) {
		t.Fatalf("identifier %q is not 32 hex characters", first)
	}

	again, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if again != first {
		t.Errorf("the identifier changed between runs: %q, then %q", first, again)
	}
}

func TestIdentifiersDiffer(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 50; i++ {
		id, err := Load(filepath.Join(t.TempDir(), "node.id"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := seen[id]; ok {
			t.Fatal("two installations got the same identifier")
		}
		seen[id] = struct{}{}
	}
}

// A broken file is not repaired silently: it means either somebody
// edited it or the disk is lying, and both deserve a human rather than a
// fresh identity.
func TestABrokenIdentifierIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.id")
	if err := os.WriteFile(path, []byte("not an identifier\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("a broken identifier was accepted")
	}
}

func TestFilePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.id")
	if _, err := Load(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o640 {
		t.Errorf("permissions %o, want 640", mode)
	}
}
