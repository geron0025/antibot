package aggregate

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// OutboxLimit is how many unsent batches are kept: about two days at
// one batch per fifteen minutes. Past it the oldest are thrown away. An
// unreachable cloud has no right to fill someone else's disk: the
// service here is the traffic, not the reporting.
const OutboxLimit = 200

const batchSuffix = ".json.gz"

// outbox keeps formed batches on disk until the cloud takes them.
//
// A batch is stored exactly as it is sent — gzipped JSON — so that a
// retry is the same bytes under the same batch key, and so that a human
// can see precisely what left the node.
type outbox struct {
	dir   string
	limit int
	log   *slog.Logger

	// mu guards the directory between the aggregator, which puts and
	// trims, and the sender, which reads and removes.
	mu sync.Mutex
}

func openOutbox(dir string, limit int, log *slog.Logger) (*outbox, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("outbox: %w", err)
	}
	return &outbox{dir: dir, limit: limit, log: log}, nil
}

// put stores a batch. A batch already there is kept: the same key means
// the same windows, and the copy already on disk was assembled first,
// from the fuller state.
func (o *outbox) put(id string, body []byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	path := filepath.Join(o.dir, id+batchSuffix)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	if err := writeFileAtomic(path, body, 0o640); err != nil {
		return err
	}

	ids, err := listBatches(o.dir)
	if err != nil {
		return err
	}
	if extra := len(ids) - o.limit; extra > 0 {
		for _, old := range ids[:extra] {
			os.Remove(filepath.Join(o.dir, old+batchSuffix))
		}
		o.log.Warn("the outbox is full: the oldest unsent batches are thrown away",
			"thrown", extra, "limit", o.limit)
	}
	return nil
}

func (o *outbox) list() ([]string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return listBatches(o.dir)
}

func (o *outbox) read(id string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return os.ReadFile(filepath.Join(o.dir, id+batchSuffix))
}

func (o *outbox) remove(id string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if err := os.Remove(filepath.Join(o.dir, id+batchSuffix)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		o.log.Error("a sent batch was not removed from the outbox", "batch", id, "err", err)
	}
}

// listBatches returns the batch keys, oldest first. The key begins with
// the start of the first window, so the order of names is the order of
// time.
func listBatches(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, batchSuffix) {
			continue
		}
		ids = append(ids, strings.TrimSuffix(name, batchSuffix))
	}
	sort.Strings(ids)
	return ids, nil
}

// Outbox lists the unsent batches in a state directory, oldest first.
// For the antibot aggregate command: whoever runs the node must be able
// to see what is about to leave it.
func Outbox(stateDir string) ([]string, error) {
	ids, err := listBatches(filepath.Join(stateDir, "outbox"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return ids, err
}

// ReadBatch returns an unsent batch as plain JSON — the very bytes that
// will go over the wire, unzipped.
func ReadBatch(stateDir, id string) ([]byte, error) {
	if id == "" || strings.ContainsAny(id, `/\`) || strings.HasPrefix(id, ".") {
		return nil, fmt.Errorf("%q is not a batch key", id)
	}
	raw, err := os.ReadFile(filepath.Join(stateDir, "outbox", id+batchSuffix))
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

// writeFileAtomic writes through a temporary file and a rename: a crash
// halfway leaves either the old file or the new one, never a torn one.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(data); err != nil {
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
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	return os.Rename(name, path)
}
