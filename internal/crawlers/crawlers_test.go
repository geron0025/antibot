package crawlers

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

var (
	google   = facts.Request{NetClass: "crawler", NetProtected: true, NetOwner: "Google"}
	openai   = facts.Request{NetClass: "crawler", NetProtected: true, NetOwner: "OpenAI"}
	gptbot   = facts.Request{NetClass: "crawler", NetOwner: "OpenAI"}
	impostor = facts.Request{UA: "Googlebot/2.1", NetClass: "hosting"}
)

// With nothing saved the verified crawlers pass, and nobody else does.
func TestPassIsOnByDefault(t *testing.T) {
	f, err := Open(filepath.Join(t.TempDir(), "crawlers.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		r    facts.Request
		pass bool
	}{"google": {google, true}, "openai": {openai, true}, "gptbot": {gptbot, false}, "impostor": {impostor, false}} {
		if f.Passes(&c.r) != c.pass {
			t.Errorf("%s: pass %v", name, !c.pass)
		}
	}
}

// The owner holds one back, or turns the pass off; another reader of
// the same file — the core, when the admin UI saved — sees it after a
// reload.
func TestOwnerDecides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared", "crawlers.json")
	admin, _ := Open(path)
	core, _ := Open(path)
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

	if err := admin.Save(Settings{Pass: true, Held: []string{"OpenAI", "", "OpenAI"}}, "owner", now); err != nil {
		t.Fatal(err)
	}
	if changed, err := core.Reload(); !changed || err != nil {
		t.Fatalf("reload: %v %v", changed, err)
	}
	if !core.Passes(&google) || core.Passes(&openai) {
		t.Error("holding OpenAI back did not work")
	}
	if s := core.Get(); len(s.Held) != 1 || s.UpdatedBy != "owner" {
		t.Errorf("settings %+v", s)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", info.Mode().Perm())
	}

	admin.Save(Settings{Pass: false}, "owner", now)
	core.Reload()
	if core.Passes(&google) {
		t.Error("the pass turned off still passes")
	}
}

// A broken file keeps what was in force rather than flipping the pass.
func TestBrokenFileKeepsTheSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crawlers.json")
	f, _ := Open(path)
	f.Save(Settings{Pass: true, Held: []string{"OpenAI"}}, "owner", time.Now())
	os.WriteFile(path, []byte("{torn"), 0o640)
	if _, err := f.Reload(); err == nil {
		t.Error("a torn file was read")
	}
	if !f.Passes(&google) || f.Passes(&openai) {
		t.Error("the settings changed on a torn file")
	}
	if _, err := Open(path); err == nil {
		t.Error("a torn file opened")
	}
}
