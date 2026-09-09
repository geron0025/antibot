// Package events writes events into NDJSON files — one line per request.
//
// The format was chosen because everything reads it: grep, jq, any
// script and antibot itself when it replays a rule over history. A
// database here would be an extra requirement on whoever installs the
// node, and would pay off only on queries that are asked once a week
// anyway.
package events

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// Options of the log.
type Options struct {
	Dir string

	// MaxSize is the limit of a single file, after which a new one is
	// started.
	MaxSize int64

	// KeepDays is how many days to keep the files. Zero means "never
	// delete", and that is a deliberately dangerous value: the disk will
	// run out silently.
	KeepDays int

	// Queue is how many events fit into the buffer before being written.
	Queue int

	Log *slog.Logger
}

func (o *Options) applyDefaults() {
	if o.MaxSize <= 0 {
		o.MaxSize = 256 << 20
	}
	if o.Queue <= 0 {
		o.Queue = 4096
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
}

// Log accepts events and writes them in the background.
type Log struct {
	o Options

	queue chan facts.Request
	done  chan struct{}
	once  sync.Once

	// Dropped counts the events that did not fit into the queue. This
	// number must be visible: a silently dropping log is worse than no
	// log at all, because people draw conclusions from it.
	Dropped atomic.Int64

	file   *os.File
	writer *json.Encoder
	size   int64
	day    string
}

func Open(o Options) (*Log, error) {
	o.applyDefaults()
	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("event log directory: %w", err)
	}

	l := &Log{
		o:     o,
		queue: make(chan facts.Request, o.Queue),
		done:  make(chan struct{}),
	}
	go l.run()
	return l, nil
}

// Write puts an event into the queue and returns immediately.
//
// If the queue is full, the event is lost. This is a deliberate trade:
// the log exists for after-the-fact analysis, and the site exists for
// its visitors, and making a visitor wait for a disk write is not
// acceptable under any circumstances.
func (l *Log) Write(r facts.Request) {
	select {
	case l.queue <- r:
	default:
		l.Dropped.Add(1)
	}
}

func (l *Log) Close() error {
	l.once.Do(func() {
		close(l.queue)
		<-l.done
	})
	return nil
}

func (l *Log) run() {
	defer close(l.done)
	defer l.closeFile()

	cleanup := time.NewTicker(time.Hour)
	defer cleanup.Stop()

	for {
		select {
		case r, open := <-l.queue:
			if !open {
				return
			}
			l.write(r)
		case <-cleanup.C:
			l.removeOld()
		}
	}
}

func (l *Log) write(r facts.Request) {
	if err := l.prepareFile(r.Time); err != nil {
		l.o.Log.Error("events: could not open the file", "err", err)
		return
	}
	if err := l.writer.Encode(r); err != nil {
		l.o.Log.Error("events: the write failed", "err", err)
		return
	}
	// An estimate of the size: the exact line length is not needed, the
	// moment of rotation is, and an error of a few bytes will not move it.
	if st, err := l.file.Stat(); err == nil {
		l.size = st.Size()
	}
	if l.size >= l.o.MaxSize {
		l.closeFile()
	}
}

func (l *Log) prepareFile(t time.Time) error {
	if t.IsZero() {
		t = time.Now()
	}
	day := t.UTC().Format("2006-01-02")

	// A change of day closes the file: that way the retention cleanup
	// works with whole files instead of cutting them from the inside.
	if l.file != nil && day != l.day {
		l.closeFile()
	}
	if l.file != nil {
		return nil
	}

	name, err := freeName(l.o.Dir, day, l.o.MaxSize)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}

	l.file, l.day, l.size = f, day, st.Size()
	l.writer = json.NewEncoder(f)
	return nil
}

// freeName picks a file name for the day: first events-DATE.ndjson, then
// one with a number if the previous one grew up to the limit.
//
// The limit passed in here is the same one rotation goes by. Otherwise,
// after a filled file is closed, the lookup would return that same file,
// and rotation by size would not work at all — the file would keep
// growing.
func freeName(dir, day string, limit int64) (string, error) {
	for n := 0; n < 10000; n++ {
		name := filepath.Join(dir, "events-"+day+".ndjson")
		if n > 0 {
			name = filepath.Join(dir, fmt.Sprintf("events-%s.%d.ndjson", day, n))
		}
		st, err := os.Stat(name)
		if os.IsNotExist(err) {
			return name, nil
		}
		if err != nil {
			return "", err
		}
		if st.Size() < limit {
			return name, nil
		}
	}
	return "", fmt.Errorf("ran out of file names for %s", day)
}

func (l *Log) closeFile() {
	if l.file == nil {
		return
	}
	if err := l.file.Close(); err != nil {
		l.o.Log.Error("events: the file did not close", "err", err)
	}
	l.file, l.writer, l.size = nil, nil, 0
}

// removeOld deletes files older than the retention period.
func (l *Log) removeOld() {
	if l.o.KeepDays <= 0 {
		return
	}
	boundary := time.Now().UTC().AddDate(0, 0, -l.o.KeepDays).Format("2006-01-02")

	files, err := filepath.Glob(filepath.Join(l.o.Dir, "events-*.ndjson"))
	if err != nil {
		l.o.Log.Error("events: the cleanup failed", "err", err)
		return
	}
	sort.Strings(files)

	for _, f := range files {
		day := dayFromName(f)
		if day == "" || day >= boundary {
			continue
		}
		if err := os.Remove(f); err != nil {
			l.o.Log.Error("events: the file was not deleted", "file", f, "err", err)
			continue
		}
		l.o.Log.Info("events: an old file was deleted", "file", filepath.Base(f))
	}
}

// dayFromName extracts the date out of events-2026-09-08.ndjson and
// events-2026-09-08.3.ndjson.
func dayFromName(path string) string {
	name := filepath.Base(path)
	name = strings.TrimPrefix(name, "events-")
	if len(name) < 10 {
		return ""
	}
	day := name[:10]
	if _, err := time.Parse("2006-01-02", day); err != nil {
		return ""
	}
	return day
}
