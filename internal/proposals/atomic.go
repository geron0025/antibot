package proposals

import (
	"os"
	"path/filepath"
)

// writeAtomic replaces a file whole, through a temporary name and a
// rename, the same way rules.Store.Write and catalog.Store.Install do:
// two processes read this directory at once — the core and the admin
// UI — and neither must ever see a half-written file.
func writeAtomic(path string, contents []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proposals-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(contents); err != nil {
		tmp.Close()
		return err
	}
	// Sync before the rename: otherwise after a power cut a file of
	// zero length ends up in place of the one it replaced.
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, mode); err != nil {
		return err
	}
	return os.Rename(name, path)
}
