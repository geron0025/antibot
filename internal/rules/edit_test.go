package rules

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func curlRule(id string) Rule {
	return Rule{
		ID: id, Scope: []string{"*"}, Mode: Shadow,
		Condition: Condition{Field: "ua", Op: "contains", Value: []byte(`"curl"`)},
		Action:    Action{Type: Block},
	}
}

// Adding and removing go the one path every change takes, and say what
// went wrong in a way a caller can tell apart.
func TestAddAndRemove(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.json")
	store, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Add(curlRule("block-curl")); err != nil {
		t.Fatal(err)
	}
	var exists *RuleExistsError
	if err := store.Add(curlRule("block-curl")); !errors.As(err, &exists) {
		t.Fatalf("the same id twice: %v", err)
	}
	bad := curlRule("bad")
	bad.Condition.Field = "useragent"
	var invalid *InvalidError
	if err := store.Add(bad); !errors.As(err, &invalid) {
		t.Fatalf("an unknown field: %v", err)
	}

	// A rule written into the file by hand in the meantime survives.
	list, _ := Read(path)
	raw, _ := json.Marshal(File{Version: FormatVersion, Rules: append(list, curlRule("by-hand"))})
	if err := os.WriteFile(path, raw, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(curlRule("from-api")); err != nil {
		t.Fatal(err)
	}
	if list, _ := Read(path); len(list) != 3 {
		t.Fatalf("%d rules after an add over a hand edit", len(list))
	}

	if err := store.Remove("by-hand"); err != nil {
		t.Fatal(err)
	}
	var missing *NoRuleError
	if err := store.Remove("by-hand"); !errors.As(err, &missing) {
		t.Fatalf("removing twice: %v", err)
	}
	if err := store.Toggle("nothing", true); !errors.As(err, &missing) {
		t.Fatalf("toggling nothing: %v", err)
	}
	if err := store.SetMode("block-curl", "loud"); !errors.As(err, &invalid) {
		t.Fatalf("a mode that does not exist: %v", err)
	}
	if len(store.Set().All()) != 2 {
		t.Fatalf("in memory: %d rules", len(store.Set().All()))
	}
}

// Changes arriving at once all land: none starts from a file another is
// about to replace.
func TestChangesAtOnceAllLand(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "rules.json"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := store.Add(curlRule(fmt.Sprintf("rule-%02d", i))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	if list, _ := Read(store.Path()); len(list) != 12 {
		t.Fatalf("%d of 12 rules landed", len(list))
	}
}
