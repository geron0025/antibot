package aggregate

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// An unreachable cloud must not fill the disk: past the limit the
// oldest are thrown away and the newest kept.
func TestOutboxKeepsTheNewest(t *testing.T) {
	box, err := openOutbox(t.TempDir(), 3, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := box.put(fmt.Sprintf("b-%d", i), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	ids, _ := box.list()
	if fmt.Sprint(ids) != "[b-3 b-4 b-5]" {
		t.Fatalf("kept %v", ids)
	}
}

// The same key means the same windows; the copy already there came
// from the fuller state and stays.
func TestOutboxKeepsTheFirstCopy(t *testing.T) {
	dir := t.TempDir()
	box, _ := openOutbox(dir, 3, slog.Default())
	box.put("b-1", []byte("first"))
	box.put("b-1", []byte("second"))
	raw, _ := os.ReadFile(filepath.Join(dir, "b-1"+batchSuffix))
	if string(raw) != "first" {
		t.Fatalf("got %q", raw)
	}
}

func TestReadBatchStaysInTheOutbox(t *testing.T) {
	for _, id := range []string{"", "../state", "a/b", `a\b`, ".tmp-1"} {
		if _, err := ReadBatch(t.TempDir(), id); err == nil {
			t.Errorf("%q was read", id)
		}
	}
}
