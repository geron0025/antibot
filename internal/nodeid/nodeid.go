// Package nodeid holds the identifier of this installation.
//
// The cloud needs it for one thing: to tell installations apart. It is
// not derived from a domain, an address or the hardware, and it must not
// be — recognizing whose node this is was never the point, and an
// identifier that reveals it would make the aggregate less anonymous
// than the format promises.
package nodeid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// valid is the shape the aggregate format fixes: 32 hex characters.
var valid = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Load reads the identifier, creating it on the first run.
//
// Created once and kept on disk: an identifier regenerated on every
// start would make one installation look like a new one every restart,
// and the counters on the far side would count nodes that never existed.
func Load(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("no node identifier file given")
	}

	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		id := strings.TrimSpace(string(raw))
		if !valid.MatchString(id) {
			// Not repaired silently: a broken identifier means either
			// somebody edited the file or the disk is lying, and both
			// deserve a human rather than a fresh identity.
			return "", fmt.Errorf("node identifier %s: %q is not 32 hex characters", path, id)
		}
		return id, nil
	case !errors.Is(err, fs.ErrNotExist):
		return "", fmt.Errorf("node identifier %s: %w", path, err)
	}

	id, err := generate()
	if err != nil {
		return "", err
	}
	if err := write(path, id); err != nil {
		return "", err
	}
	return id, nil
}

func generate() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

func write(path, id string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("node identifier directory: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".node-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.WriteString(id + "\n"); err != nil {
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
	if err := os.Chmod(name, 0o640); err != nil {
		return err
	}
	return os.Rename(name, path)
}
