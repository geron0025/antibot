package rules

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

const sampleFile = `{
  "version": 1,
  "rules": [
    {"id":"block-hosting","scope":["*"],"mode":"active","priority":100,
     "condition":{"field":"network.class","op":"eq","value":"hosting"},
     "action":{"type":"block"}}
  ]
}`

func tempFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.json")
	if contents != "" {
		if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// A node without rules is the ordinary state right after installation:
// the file is not written yet, and proxying has to happen already.
func TestAMissingFileIsNotAnError(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "none.json"), nil, nil)
	if err != nil {
		t.Fatalf("a node without a rules file did not come up: %v", err)
	}
	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionPass {
		t.Errorf("without rules everything passes, got %+v", d)
	}
}

func TestReadingAndRereading(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionBlock {
		t.Fatalf("the rule from the file was not applied: %+v", d)
	}

	// Replacing the file as a whole is what a human does with an editor.
	updated := strings.Replace(sampleFile, `"type":"block"`, `"type":"allow"`, 1)
	if err := os.WriteFile(path, []byte(updated), 0o640); err != nil {
		t.Fatal(err)
	}
	// The size changed, so the reread works even at one-second precision
	// of the file's time.
	if changed, err := s.reload(); err != nil || !changed {
		t.Fatalf("reread: changed=%v, err=%v", changed, err)
	}
	r2 := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r2); d.Action != proxy.ActionAllow {
		t.Errorf("after the file was edited the old set is in force: %+v", d)
	}
}

// A broken file must neither bring the node down nor lift the
// protection: the previous set stays in force, and the human learns about
// the error from the log.
func TestABrokenFileKeepsThePreviousSet(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte(`{"version":1,"rules":[{"id":"x"`), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reload(); err == nil {
		t.Fatal("the broken file was read without an error")
	}

	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionBlock {
		t.Errorf("the protection was lifted after the broken file: %+v", d)
	}
}

// A broken file at startup is a different matter: here the human is
// standing right there and must see the refusal at once.
func TestABrokenFileAtStartupIsAnError(t *testing.T) {
	path := tempFile(t, `{"version":1,"rules":[{"id":"a","scope":["*"],"mode":"active",
		"condition":{"field":"ja44","op":"eq","value":"x"},"action":{"type":"block"}}]}`)
	if _, err := Open(path, nil, nil); err == nil {
		t.Error("the node came up with an invalid rules file")
	}
}

func TestAForeignVersionIsRejected(t *testing.T) {
	path := tempFile(t, `{"version":99,"rules":[]}`)
	if _, err := Open(path, nil, nil); err == nil {
		t.Error("a file of a foreign version was accepted")
	}
}

// A typo in a field name is an error, not a silently skipped intention.
func TestAnUnknownFieldInTheFile(t *testing.T) {
	path := tempFile(t, `{"version":1,"rules":[{"id":"a","scope":["*"],"mode":"active",
		"enable":true,"condition":{"field":"ua","op":"eq","value":"x"},"action":{"type":"block"}}]}`)
	if _, err := Open(path, nil, nil); err == nil {
		t.Error("a rule with a typo in a field name was accepted")
	}
}

// A vanished file lifts the rules: that is a human's decision, not a
// failure.
func TestAVanishedFileLiftsTheRules(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reload(); err != nil {
		t.Fatalf("the file vanishing is not a read error: %v", err)
	}
	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionPass {
		t.Errorf("the rules survived the file being deleted: %+v", d)
	}
}

func TestTheWriteIsAtomicAndValidated(t *testing.T) {
	path := tempFile(t, "")
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// An invalid set must not reach the disk: the node would refuse to
	// read it at the next start.
	broken := []Rule{{ID: "bad", Scope: []string{"*"}, Mode: Active,
		Condition: Condition{Field: "ja44", Op: "eq", Value: []byte(`"x"`)},
		Action:    Action{Type: Block}}}
	if err := s.Write(broken); err == nil {
		t.Error("an invalid set was written")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a file was left on disk after the refusal")
	}

	valid := []Rule{{ID: "ok", Scope: []string{"example.ru"}, Mode: Active, Priority: 10,
		Condition: Condition{Field: "network.class", Op: "eq", Value: []byte(`"hosting"`)},
		Action:    Action{Type: Block}}}
	if err := s.Write(valid); err != nil {
		t.Fatal(err)
	}

	// What was written applied at once, without waiting for the watcher.
	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionBlock || d.Rule != "ok" {
		t.Errorf("the written rule is not in force: %+v", d)
	}

	// And it reads back through the same parser.
	rules, err := Read(path)
	if err != nil || len(rules) != 1 || rules[0].ID != "ok" {
		t.Errorf("we reread the wrong thing: %v, err %v", rules, err)
	}

	// No temporary files must be left after the write.
	entries, _ := os.ReadDir(filepath.Dir(path))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".rules-") {
			t.Errorf("a temporary file %s was left behind", e.Name())
		}
	}
}

// The snapshot is read without a lock on every request and swapped whole:
// the decisions during a reread must stay coherent.
func TestReadingDuringAReread(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				r := facts.Request{Host: "example.ru", NetClass: "hosting"}
				if d := s.Decide(&r); d.Action != proxy.ActionBlock && d.Action != proxy.ActionAllow {
					t.Errorf("an incoherent decision during a reread: %+v", d)
					return
				}
			}
		}
	}()

	for i := 0; i < 20; i++ {
		contents := sampleFile
		if i%2 == 0 {
			contents = strings.Replace(sampleFile, `"type":"block"`, `"type":"allow"`, 1)
		}
		if err := os.WriteFile(path, []byte(contents), 0o640); err != nil {
			t.Error(err)
			break
		}
		if _, err := s.reload(); err != nil {
			t.Error(err)
			break
		}
	}
	close(stop)
	wg.Wait()
}

// The rules file comes from outside: it may be written by hand, glued
// together by a script or sent by mistake. It must not bring the node
// down in any form.
func FuzzParse(f *testing.F) {
	f.Add(sampleFile)
	f.Add(`{"version":1,"rules":[]}`)
	f.Add(`{"version":1,"rules":[{"id":"a","scope":["*.х"],"mode":"shadow","priority":-9,
		"condition":{"not":{"any":[{"field":"ip","op":"cidr","value":["0.0.0.0/0"]}]}},
		"action":{"type":"ratelimit","limit":1,"window":"1ns","key":"ja4"}}]}`)

	// One limiter for the whole run: it is stateful, and creating one per
	// call would mean measuring the garbage collector rather than the
	// parsing.
	//
	// The number of keys is bounded on purpose: in the node the map is
	// cleaned by the sweeper, and here there is none, so over a million
	// runs it grows to the limit — eight parallel workers then drive the
	// machine into swap, and the fuzzer freezes without finding anything.
	limiter := NewWindows()
	limiter.MaxKeys = 1024

	f.Fuzz(func(t *testing.T, s string) {
		start := time.Now()
		set, err := Parse([]byte(s), limiter)
		if err == nil {
			// A set that was built must be applicable, whatever is in it.
			r := facts.Request{Host: "example.ru", IP: "203.0.113.7", Method: "GET"}
			set.Decide(&r)
		}
		// Time is behaviour too: a rules file whose parsing takes seconds
		// is a stall of the node on every reread.
		if d := time.Since(start); d > time.Second {
			t.Fatalf("parsing and applying took %v", d)
		}
	})
}

// Enabling and disabling is the only change to the rules available from
// outside the command line. It goes through the same write and the same
// validation.
func TestToggle(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Toggle("block-hosting", false); err != nil {
		t.Fatal(err)
	}
	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionPass {
		t.Errorf("a disabled rule keeps working: %+v", d)
	}

	if err := s.Toggle("block-hosting", true); err != nil {
		t.Fatal(err)
	}
	r2 := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r2); d.Action != proxy.ActionBlock {
		t.Errorf("an enabled rule does not work: %+v", d)
	}

	if err := s.Toggle("no such rule", false); err == nil {
		t.Error("toggling a non-existent rule passed silently")
	}
}

// Moving between shadow and active goes through the same write: a shadow
// rule only marks the event, an active one decides.
func TestSetMode(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetMode("block-hosting", Shadow); err != nil {
		t.Fatal(err)
	}
	r := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r); d.Action != proxy.ActionPass || len(r.Shadow) != 1 {
		t.Errorf("a shadow rule decided: %+v, shadow %v", d, r.Shadow)
	}

	if err := s.SetMode("block-hosting", Active); err != nil {
		t.Fatal(err)
	}
	r2 := facts.Request{Host: "example.ru", NetClass: "hosting"}
	if d := s.Decide(&r2); d.Action != proxy.ActionBlock {
		t.Errorf("an active rule does not decide: %+v", d)
	}

	list, err := Read(path)
	if err != nil || len(list) != 1 || list[0].Mode != Active {
		t.Errorf("the file says %+v, %v", list, err)
	}

	if err := s.SetMode("block-hosting", "loud"); err == nil {
		t.Error("a made-up mode passed")
	}
	if err := s.SetMode("no such rule", Active); err == nil {
		t.Error("a non-existent rule passed silently")
	}
}

// The file may have been edited by hand while the admin UI was open:
// writing over a stale snapshot would silently undo somebody else's
// changes.
func TestTogglingDoesNotLoseForeignEdits(t *testing.T) {
	path := tempFile(t, sampleFile)
	s, err := Open(path, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// An edit made past the node: a second rule was added.
	twoRules := strings.Replace(sampleFile, "  ]\n}", `   ,{"id":"by-hand","scope":["*"],"mode":"shadow","priority":1,
     "condition":{"field":"method","op":"eq","value":"GET"},
     "action":{"type":"block"}}
  ]
}`, 1)
	if err := os.WriteFile(path, []byte(twoRules), 0o640); err != nil {
		t.Fatal(err)
	}

	if err := s.Toggle("block-hosting", false); err != nil {
		t.Fatal(err)
	}

	rules, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Fatalf("%d rules left, want 2: the hand edit was lost", len(rules))
	}
}
