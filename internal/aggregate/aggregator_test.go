package aggregate

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/proxy"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func testAggregator(t *testing.T, dir string, c *clock) *Aggregator {
	t.Helper()
	a, err := Open(Options{
		Dir: dir, URL: "http://127.0.0.1:1/ingest", Token: "tok",
		NodeID: testNode, Version: "0.2.0",
		Served: func(h string) bool { return h == "shop.example.ru" },
		now:    c.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func at(ts time.Time, ip string) facts.Request {
	r := request(ip, "shop.example.ru")
	r.Time = ts
	return r
}

func outboxBatches(t *testing.T, a *Aggregator) []Batch {
	t.Helper()
	ids, err := a.outbox.list()
	if err != nil {
		t.Fatal(err)
	}
	var out []Batch
	for _, id := range ids {
		raw, err := a.outbox.read(id)
		if err != nil {
			t.Fatal(err)
		}
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		var b Batch
		if err := json.NewDecoder(zr).Decode(&b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// No token, no aggregator: the sending code cannot even start, and it
// leaves nothing behind on disk.
func TestNoTokenNoAggregator(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "aggregate")
	if _, err := Open(Options{Dir: dir, URL: "http://x", NodeID: testNode}); err == nil {
		t.Fatal("opened without a token")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("a node without a token created the state directory")
	}
	if _, err := Open(Options{Dir: dir, URL: "http://x", Token: "t", NodeID: "short"}); err == nil {
		t.Fatal("opened with a malformed node identifier")
	}
}

func TestWindowClosesAfterGrace(t *testing.T) {
	c := &clock{t0.Add(time.Minute)}
	a := testAggregator(t, t.TempDir(), c)
	a.add(at(t0.Add(time.Minute), "203.0.113.1"))

	a.closeWindows(t0.Add(WindowLength + grace - time.Second))
	if len(a.pending) != 0 {
		t.Fatal("the window closed before the grace ran out")
	}
	a.closeWindows(t0.Add(WindowLength + grace))
	if len(a.pending) != 1 || len(a.windows) != 0 {
		t.Fatalf("pending %d, open %d", len(a.pending), len(a.windows))
	}
}

// A window that closed must not change. A late request lands in the
// oldest open window instead.
func TestLateRequestDoesNotReopen(t *testing.T) {
	c := &clock{}
	a := testAggregator(t, t.TempDir(), c)
	a.add(at(t0.Add(time.Minute), "203.0.113.1"))
	a.closeWindows(t0.Add(WindowLength + grace))

	a.add(at(t0.Add(3*time.Minute), "203.0.113.2"))
	if _, ok := a.windows[t0]; ok {
		t.Fatal("a closed window was reopened")
	}
	if _, ok := a.windows[t0.Add(WindowLength)]; !ok {
		t.Fatal("the late request is not in the next window")
	}
}

// The window is chosen by when the request finished.
func TestWindowByCompletion(t *testing.T) {
	a := testAggregator(t, t.TempDir(), &clock{})
	r := at(t0.Add(4*time.Minute), "203.0.113.1")
	r.Duration = 2 * time.Minute
	a.add(r)
	if _, ok := a.windows[t0.Add(WindowLength)]; !ok {
		t.Fatal("a request finishing at 17:06 went to the 17:00 window")
	}
}

func fill(a *Aggregator, start time.Time, keys int) {
	for i := 0; i < keys; i++ {
		a.add(at(start.Add(time.Minute), fmt.Sprintf("10.%d.%d.1", i>>8&255, i&255)))
	}
}

// The schema caps a batch at MaxRows rows. Windows are packed whole,
// never split, and a batch that would overflow starts a new one.
func TestBatchesRespectTheRowLimit(t *testing.T) {
	c := &clock{}
	a := testAggregator(t, t.TempDir(), c)
	for i := 0; i < 3; i++ {
		fill(a, t0.Add(time.Duration(i)*WindowLength), 2000)
	}
	c.t = t0.Add(3*WindowLength + grace)
	a.closeWindows(c.t)
	a.flush(c.t)

	batches := outboxBatches(t, a)
	if len(batches) != 2 {
		t.Fatalf("%d batches, want 2 (4000 + 2000 rows)", len(batches))
	}
	if len(batches[0].Rows) != 4000 || len(batches[1].Rows) != 2000 {
		t.Fatalf("rows per batch: %d, %d", len(batches[0].Rows), len(batches[1].Rows))
	}
	if batches[1].Rows[0].Window != "2026-09-08T17:10:00Z" {
		t.Fatalf("the second batch starts at %s", batches[1].Rows[0].Window)
	}
	if len(a.pending) != 0 {
		t.Fatalf("%d windows still pending", len(a.pending))
	}
}

// A batch names one fact set version, so a change of version starts a
// new batch.
func TestFactsVersionSplitsBatches(t *testing.T) {
	c := &clock{}
	a := testAggregator(t, t.TempDir(), c)
	version := 136
	a.o.FactsVersion = func() int { return version }

	fill(a, t0, 3)
	a.closeWindows(t0.Add(WindowLength + grace))
	version = 137
	fill(a, t0.Add(WindowLength), 3)
	a.closeWindows(t0.Add(2*WindowLength + grace))
	a.flush(t0.Add(2*WindowLength + grace))

	batches := outboxBatches(t, a)
	if len(batches) != 2 || batches[0].FactsVersion != 136 || batches[1].FactsVersion != 137 {
		t.Fatalf("batches: %d, versions %v", len(batches), batches)
	}
}

// The key is derived from the windows: the same windows packed again
// after a crash carry the same key, and the cloud drops the repeat.
func TestBatchKeyIsDerived(t *testing.T) {
	id := batchID(testNode, t0)
	if id != testNode+"-20260908T1700Z" {
		t.Fatalf("key %q", id)
	}
	if len(id) < 8 || len(id) > 64 {
		t.Fatalf("key length %d is outside the schema's 8..64", len(id))
	}
}

// The open window survives a restart, sketches included.
func TestSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	c := &clock{t0.Add(time.Minute)}
	a := testAggregator(t, dir, c)
	for i := 0; i < 100; i++ {
		r := at(t0.Add(time.Minute), fmt.Sprintf("203.0.113.%d", i))
		r.Path = fmt.Sprintf("/p/%d", i)
		a.add(r)
	}
	fill(a, t0.Add(-WindowLength), 2)
	a.closeWindows(t0.Add(grace))
	var paths, addrs uint64
	for _, c := range a.windows[t0].rows {
		paths, addrs = c.Paths.estimate(), c.Addrs.estimate()
	}
	a.save()

	b := testAggregator(t, dir, c)
	if len(b.pending) != 1 || len(b.windows) != 1 || !b.openFrom.Equal(t0) {
		t.Fatalf("restored: pending %d, open %d, open from %s", len(b.pending), len(b.windows), b.openFrom)
	}
	b.closeWindows(t0.Add(WindowLength + grace))
	rows := b.pending[1].Rows
	// A hundred values are past the exact list, so the counts are
	// estimates — and must be the very estimates the first run had.
	if len(rows) != 1 || rows[0].Requests != 100 || rows[0].UniqPaths != paths || rows[0].UniqAddrs != addrs {
		t.Fatalf("restored row: %+v", rows)
	}

	st, err := ReadState(dir)
	if err != nil || len(st.Pending) != 1 || st.Pending[0].Requests != 2 {
		t.Fatalf("summary %+v, %v", st, err)
	}
}

func TestBrokenStateIsSetAside(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, stateFile), []byte("{torn"), 0o640)
	a := testAggregator(t, dir, &clock{})
	if len(a.windows) != 0 {
		t.Fatal("something restored from a torn file")
	}
	if _, err := os.Stat(filepath.Join(dir, stateFile+".broken")); err != nil {
		t.Fatal("the broken file was not kept for inspection")
	}
}

// Run saves on the way out, and what was queued is counted.
func TestRunSavesOnStop(t *testing.T) {
	dir := t.TempDir()
	a := testAggregator(t, dir, &clock{time.Now()})
	ctx, cancel := contextWithCancel(t)
	done := make(chan struct{})
	go func() {
		a.Run(ctx)
		close(done)
	}()
	for i := 0; i < 10; i++ {
		r := request("203.0.113.1", "shop.example.ru")
		r.Time = time.Now()
		a.Write(r)
	}
	cancel()
	<-done

	st, err := ReadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, w := range st.Open {
		total += w.Requests
	}
	if total != 10 {
		t.Fatalf("%d requests saved, want 10", total)
	}
}

// The batch the node posts must pass the schema the cloud checks it
// against. The schema is the arbiter; this test reads it rather than
// restating it.
func TestBatchMatchesTheSchema(t *testing.T) {
	c := &clock{}
	a := testAggregator(t, t.TempDir(), c)
	a.o.FactsVersion = func() int { return 137 }

	// Every kind of row: an ordinary one, a plain-HTTP one without TLS
	// or HTTP/2, one to a junk host, one without an address, and enough
	// keys to produce ~rest.
	fill(a, t0, MaxRows+2)
	plain := at(t0.Add(time.Minute), "2001:db8::1")
	plain.JA4, plain.H2, plain.UA, plain.Status = "", "", "", 0
	plain.Decision = proxy.ActionBlock
	a.add(plain)
	junk := at(t0.Add(time.Minute), "")
	junk.Host = strings.Repeat("x", 300)
	junk.Method = "BREW"
	a.add(junk)

	a.closeWindows(t0.Add(WindowLength + grace))
	a.flush(t0.Add(WindowLength + grace))

	schema := loadSchema(t)
	ids, _ := a.outbox.list()
	if len(ids) != 1 {
		t.Fatalf("%d batches", len(ids))
	}
	raw, _ := a.outbox.read(ids[0])
	zr, _ := gzip.NewReader(bytes.NewReader(raw))
	body, _ := io.ReadAll(zr)

	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if errs := validate(schema, schema, doc, "$"); len(errs) > 0 {
		t.Fatalf("the batch does not match the schema:\n%s", strings.Join(errs[:min(len(errs), 20)], "\n"))
	}

	var b Batch
	json.Unmarshal(body, &b)
	if len(b.Rows) != MaxRows || b.Rows[len(b.Rows)-1].Key != restKey {
		t.Fatalf("%d rows, last %+v", len(b.Rows), b.Rows[len(b.Rows)-1].Key)
	}
}

// The example in the protocol document passes the same check — in both
// languages, since a translation that drifted is just as wrong.
func TestProtocolExampleMatchesTheSchema(t *testing.T) {
	schema := loadSchema(t)
	fence := regexp.MustCompile("(?s)```json\n(.*?)```")
	for _, lang := range []string{"ru", "en"} {
		path := filepath.Join("..", "..", "docs", lang, "protocol", "aggregate.md")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		blocks := fence.FindAllSubmatch(raw, -1)
		if len(blocks) == 0 {
			t.Fatalf("%s: no JSON example", path)
		}
		for _, m := range blocks {
			var doc any
			if err := json.Unmarshal(m[1], &doc); err != nil {
				t.Fatalf("%s: %v", path, err)
			}
			if errs := validate(schema, schema, doc, "$"); len(errs) > 0 {
				t.Errorf("%s: the example does not match the schema:\n%s", path, strings.Join(errs, "\n"))
			}
		}
	}
}
