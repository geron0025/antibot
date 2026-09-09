package events

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

func logFrom(t *testing.T, name, contents string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o640); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The files of a single day are read in the order they were written: by
// name events-...1.ndjson comes before events-....ndjson, and by time it
// comes after. For the rate limiter in a replay those are different
// numbers.
func TestFileOrder(t *testing.T) {
	dir := t.TempDir()
	names := []string{
		"events-2026-09-09.ndjson",
		"events-2026-09-08.2.ndjson",
		"events-2026-09-08.ndjson",
		"events-2026-09-08.1.ndjson",
		"foreign.txt",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	files, err := Files(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"events-2026-09-08.ndjson",
		"events-2026-09-08.1.ndjson",
		"events-2026-09-08.2.ndjson",
		"events-2026-09-09.ndjson",
	}
	if len(files) != len(want) {
		t.Fatalf("%d files, want %d: %v", len(files), len(want), files)
	}
	for i := range want {
		if filepath.Base(files[i]) != want[i] {
			t.Errorf("position %d holds %s, want %s", i, filepath.Base(files[i]), want[i])
		}
	}

	reversed := Reversed(files)
	if filepath.Base(reversed[0]) != "events-2026-09-09.ndjson" {
		t.Errorf("the reverse order starts with %s", filepath.Base(reversed[0]))
	}
}

// A torn line is an ordinary thing: the log may have been copied while it
// was being written. Reading must count through to the end and say how
// many lines were not understood.
func TestBrokenLinesDoNotBreakReading(t *testing.T) {
	dir := logFrom(t, "events-2026-09-08.ndjson",
		`{"t":"2026-09-08T12:00:00Z","ip":"203.0.113.1","host":"a.ru"}
{"t":"2026-09-08T12:00:01Z","ip":"203.0.11
{"t":"2026-09-08T12:00:02Z","ip":"203.0.113.3","host":"a.ru"}
`)
	var collected int
	result, err := Read(Filter{Dir: dir}, func(facts.Request) error {
		collected++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if collected != 2 || result.Broken != 1 || result.Read != 3 {
		t.Errorf("collected %d, broken %d, read %d; want 2, 1, 3",
			collected, result.Broken, result.Read)
	}
}

func TestFilterByTime(t *testing.T) {
	dir := logFrom(t, "events-2026-09-08.ndjson",
		`{"t":"2026-09-08T12:00:00Z","ip":"203.0.113.1"}
{"t":"2026-09-08T14:00:00Z","ip":"203.0.113.2"}
{"t":"2026-09-08T16:00:00Z","ip":"203.0.113.3"}
`)
	var addrs []string
	_, err := Read(Filter{
		Dir:  dir,
		From: time.Date(2026, 9, 8, 13, 0, 0, 0, time.UTC),
		To:   time.Date(2026, 9, 8, 15, 0, 0, 0, time.UTC),
	}, func(r facts.Request) error {
		addrs = append(addrs, r.IP)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "203.0.113.2" {
		t.Errorf("selected %v, want only 203.0.113.2", addrs)
	}
}

// Stopping from fn is what makes "show the last hundred events" work:
// there is no point reading two weeks of log for a hundred lines.
func TestStoppingTheRead(t *testing.T) {
	dir := logFrom(t, "events-2026-09-08.ndjson",
		`{"t":"2026-09-08T12:00:00Z","ip":"203.0.113.1"}
{"t":"2026-09-08T12:00:01Z","ip":"203.0.113.2"}
{"t":"2026-09-08T12:00:02Z","ip":"203.0.113.3"}
`)
	var count int
	result, err := Read(Filter{Dir: dir}, func(facts.Request) error {
		count++
		if count == 2 {
			return ErrStop
		}
		return nil
	})
	if err != nil {
		t.Fatalf("stopping must not be an error: %v", err)
	}
	if count != 2 || result.Matched != 2 {
		t.Errorf("%d events read, want 2", count)
	}
}

// Exactly what the log writes is what gets read: end to end, not through
// a "similar format".
func TestReadsWhatItWrites(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	l.Write(facts.Request{
		Time: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC),
		IP:   "203.0.113.1", Host: "a.ru", UA: "curl/8.4",
		JA4: "t13d1516h2", Decision: "block", Rule: "block-hosting",
		Shadow: []string{"watch-curl"},
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	var read []facts.Request
	if _, err := Read(Filter{Dir: dir}, func(r facts.Request) error {
		read = append(read, r)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(read) != 1 {
		t.Fatalf("%d events read", len(read))
	}
	r := read[0]
	if r.UA != "curl/8.4" || r.JA4 != "t13d1516h2" || r.Rule != "block-hosting" {
		t.Errorf("the signals were lost: %+v", r)
	}
	if len(r.Shadow) != 1 || r.Shadow[0] != "watch-curl" {
		t.Errorf("the shadows were lost: %v", r.Shadow)
	}
}
