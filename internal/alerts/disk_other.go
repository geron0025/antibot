//go:build !(linux || darwin || freebsd)

package alerts

import "errors"

// freeBytes is not known on this system; the disk check stays silent.
func freeBytes(string) (uint64, error) {
	return 0, errors.New("the free space is not known on this system")
}
