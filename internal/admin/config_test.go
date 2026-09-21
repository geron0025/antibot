package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The example the documentation points to is read with the same code as
// the real settings.
func TestExampleAdminConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "deploy", "admin.example.yaml")
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("the example admin settings do not parse: %v", err)
	}
	if cfg.Core.Socket == "" || cfg.Core.RulesFile == "" {
		t.Fatalf("%+v", cfg.Core)
	}
}

// A typo is an error, not a silently ignored intention.
func TestAdminConfigRefusesUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.yaml")
	if err := os.WriteFile(path, []byte("listen: 127.0.0.1:8090\ncore:\n  sockett: /tmp/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil || !strings.Contains(err.Error(), "sockett") {
		t.Fatalf("err = %v", err)
	}
}
