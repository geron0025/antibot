package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The core carries no admin UI: no templates, no passwords, no uploads.
// A vulnerability in the admin UI must not be able to sit in the process
// that holds the site's traffic, and this keeps an import from quietly
// bringing it back.
func TestTheCoreDoesNotCarryTheAdminUI(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasSuffix(pkg, "/internal/admin") {
			t.Fatalf("the core depends on %s", pkg)
		}
	}
}
