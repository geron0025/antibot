package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// Filter says which events to read.
type Filter struct {
	// Dir holds the log files. Either it or Files.
	Dir   string
	Files []string

	// From and To cut events off by time. Zero means no bound.
	From, To time.Time
}

// Result of a read. Broken lines are counted separately and do not
// interrupt reading: the log may have been copied while it was being
// written, and a torn last line is no reason to give up the rest.
type Result struct {
	Read    int
	Matched int
	Broken  int
}

// Read walks the log and yields events one by one.
//
// There is a single reader in the project — for the rule replay and for
// the admin UI summary alike. Should they drift apart, a human would see
// one set of numbers in the admin UI and another in the replay, with no
// way to tell which are real.
//
// Returning an error from fn stops the reading: that is how "show the
// last hundred events" works without reading two weeks of log in full.
func Read(f Filter, fn func(facts.Request) error) (Result, error) {
	var result Result

	files := f.Files
	if len(files) == 0 {
		var err error
		files, err = Files(f.Dir)
		if err != nil {
			return result, err
		}
	}

	for _, path := range files {
		stop, err := readFile(path, f, &result, fn)
		if err != nil {
			return result, err
		}
		if stop {
			return result, nil
		}
	}
	return result, nil
}

// ErrStop ends the reading from fn without an error.
var ErrStop = fmt.Errorf("reading stopped")

func readFile(path string, f Filter, result *Result, fn func(facts.Request) error) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("event log %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// An event line with a long User-Agent and a header composition
	// easily exceeds bufio's 64 KB default.
	scanner.Buffer(make([]byte, 0, 64<<10), 4<<20)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		result.Read++

		var r facts.Request
		if err := json.Unmarshal(line, &r); err != nil {
			result.Broken++
			continue
		}
		if !f.inWindow(r.Time) {
			continue
		}
		result.Matched++

		if err := fn(r); err != nil {
			if err == ErrStop {
				return true, nil
			}
			return false, err
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return false, fmt.Errorf("event log %s: %w", path, err)
	}
	return false, nil
}

func (f *Filter) inWindow(t time.Time) bool {
	if !f.From.IsZero() && t.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !t.Before(f.To) {
		return false
	}
	return true
}

var fileNameRe = regexp.MustCompile(`^events-(\d{4}-\d{2}-\d{2})(?:\.(\d+))?\.ndjson$`)

// Files lists the log files in chronological order.
//
// Chronological rather than by name: events-2026-09-08.1 was written
// after events-2026-09-08 yet comes before it alphabetically. For the
// rate limiter in a replay that is the difference between real numbers
// and invented ones.
func Files(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("event log directory %s: %w", dir, err)
	}

	type logFile struct {
		path string
		day  string
		num  int
	}
	var matching []logFile

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		parts := fileNameRe.FindStringSubmatch(e.Name())
		if parts == nil {
			continue
		}
		num := 0
		if parts[2] != "" {
			num, _ = strconv.Atoi(parts[2])
		}
		matching = append(matching, logFile{
			path: filepath.Join(dir, e.Name()), day: parts[1], num: num,
		})
	}

	sort.Slice(matching, func(a, b int) bool {
		if matching[a].day != matching[b].day {
			return matching[a].day < matching[b].day
		}
		return matching[a].num < matching[b].num
	})

	paths := make([]string, 0, len(matching))
	for _, f := range matching {
		paths = append(paths, f.path)
	}
	return paths, nil
}

// Reversed flips the list of files: the latest events lie at the end of
// the last file, and "show the last hundred" reads from it rather than
// from a log two weeks old.
func Reversed(files []string) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[len(files)-1-i] = f
	}
	return out
}
