package events

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

func readEvents(t *testing.T, dir string) []facts.Request {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "events-*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var out []facts.Request
	for _, f := range files {
		file, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var r facts.Request
			if err := json.Unmarshal(scanner.Bytes(), &r); err != nil {
				t.Fatalf("%s: the line does not parse: %v", f, err)
			}
			out = append(out, r)
		}
		file.Close()
	}
	return out
}

func TestEventsAreWrittenAndRead(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}

	l.Write(facts.Request{
		Time: time.Now(), Host: "shop.example.ru", Method: "GET",
		Path: "/", JA4: "t13d1516h2_8daaf6152771_02713d6af862", Decision: "pass",
	})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	events := readEvents(t, dir)
	if len(events) != 1 {
		t.Fatalf("%d events written, want 1", len(events))
	}
	if events[0].Host != "shop.example.ru" || events[0].JA4 == "" {
		t.Errorf("the event lost fields: %+v", events[0])
	}
}

// Rotation by size: a file that grew up to the limit is closed and the
// writes continue into the next one. A mistake here means a file growing
// forever.
func TestRotationBySize(t *testing.T) {
	dir := t.TempDir()
	l, err := Open(Options{Dir: dir, MaxSize: 512})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		l.Write(facts.Request{
			Time: time.Now(), Host: "shop.example.ru",
			Path: strings.Repeat("d", 40), Decision: "pass",
		})
	}
	l.Close()

	files, _ := filepath.Glob(filepath.Join(dir, "events-*.ndjson"))
	if len(files) < 2 {
		t.Fatalf("no rotation happened: %d files", len(files))
	}
	if got := len(readEvents(t, dir)); got != 50 {
		t.Errorf("%d events out of 50 survived the rotation", got)
	}
	for _, f := range files {
		st, _ := os.Stat(f)
		if st.Size() > 512+256 {
			t.Errorf("%s grew to %d bytes with a limit of 512", filepath.Base(f), st.Size())
		}
	}
}

func TestCleanupRemovesOnlyOldFiles(t *testing.T) {
	dir := t.TempDir()
	old := filepath.Join(dir, "events-2020-01-01.ndjson")
	fresh := filepath.Join(dir, "events-"+time.Now().UTC().Format("2006-01-02")+".ndjson")
	foreign := filepath.Join(dir, "note.txt")
	for _, f := range []string{old, fresh, foreign} {
		if err := os.WriteFile(f, []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}

	l := &Log{o: Options{Dir: dir, KeepDays: 7}}
	l.o.applyDefaults()
	l.removeOld()

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Error("the old file was not deleted")
	}
	for _, f := range []string{fresh, foreign} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was deleted for nothing", filepath.Base(f))
		}
	}
}

// The hot path has no right to wait for the disk: on a full queue the
// event is lost, but Write returns at once.
func TestFullQueueDoesNotBlock(t *testing.T) {
	l := &Log{queue: make(chan facts.Request, 1)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 1000; i++ {
			l.Write(facts.Request{Host: "shop.example.ru"})
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Write blocked on a full queue")
	}
	if l.Dropped.Load() == 0 {
		t.Error("the drops were not counted — the log loses events silently")
	}
}
