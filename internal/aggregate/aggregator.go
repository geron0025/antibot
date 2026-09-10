// Package aggregate counts the traffic in five-minute windows and sends
// the counts to the cloud.
//
// What goes out is fixed by docs/*/protocol/aggregate.md; this package
// is its execution. Without a subscription token it does not exist: not
// "turned off", but never assembled, because there is nobody to send to.
//
// Nothing here is on the hot path. The handler drops a copy of the
// request into a queue and moves on; counting, closing windows, writing
// to disk and posting to the cloud all happen in goroutines of their
// own, and a full queue loses the event rather than delay a visitor.
package aggregate

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync/atomic"
	"time"

	"github.com/geron0025/antibot/internal/facts"
)

// FormatVersion is the aggregate format this node speaks.
const FormatVersion = 1

const (
	// grace is how long a window waits after its end before it closes.
	// A request is counted when it finishes, and the queue in front of
	// the counter is not instant.
	grace = 10 * time.Second

	// saveEvery bounds what a crash loses: at most this much of the open
	// window. A graceful stop loses nothing.
	saveEvery = time.Minute

	stateFile = "state.json"
)

var validNode = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Options of the aggregator.
type Options struct {
	// Dir keeps the open windows across a restart and the batches the
	// cloud has not taken yet.
	Dir string

	URL     string
	Token   string
	NodeID  string
	Version string

	// Interval is how often closed windows are packed and sent.
	Interval time.Duration

	// Served tells a protected domain from whatever the client put in
	// Host. Nil means every well-formed name counts.
	Served func(host string) bool

	// FactsVersion is the fact set in force: the cloud needs it to know
	// which base judged ua_matches_ja4.
	FactsVersion func() int

	Queue int
	Log   *slog.Logger

	// Client and now are replaced in tests.
	Client *http.Client
	now    func() time.Time
}

// Aggregator counts events and hands batches to the sender.
type Aggregator struct {
	o      Options
	queue  chan facts.Request
	outbox *outbox
	sender *sender

	// Dropped counts events that did not fit into the queue. A count
	// that loses events silently would be believed.
	Dropped atomic.Int64

	// Owned by the Run goroutine.
	windows  map[time.Time]*window
	openFrom time.Time
	pending  []closedWindow
}

// closedWindow is a window that is finished and waits for its batch.
// Its rows no longer change, so they are kept in their wire form.
type closedWindow struct {
	Start time.Time `json:"start"`
	Facts int       `json:"facts"`
	Rows  []Row     `json:"rows"`
}

// Batch is the body of one POST.
type Batch struct {
	Format       int    `json:"format"`
	Batch        string `json:"batch"`
	Node         string `json:"node"`
	NodeVersion  string `json:"node_version,omitempty"`
	FactsVersion int    `json:"facts_version,omitempty"`
	SentAt       string `json:"sent_at"`
	Rows         []Row  `json:"rows"`
}

// Open assembles the aggregator and restores what the previous run left.
//
// It refuses to exist without a token, an address and an identifier:
// the promise is that a node without a token sends nothing, and the
// cheapest way to keep it is for the sending code to be unable to start.
func Open(o Options) (*Aggregator, error) {
	switch {
	case o.Token == "":
		return nil, errors.New("no subscription token: the aggregate has no addressee")
	case o.URL == "":
		return nil, errors.New("no cloud address: nowhere to send the aggregate")
	case !validNode.MatchString(o.NodeID):
		return nil, fmt.Errorf("node identifier %q is not 32 hex characters", o.NodeID)
	case o.Dir == "":
		return nil, errors.New("no state directory for the aggregate")
	}
	if o.Interval <= 0 {
		o.Interval = 15 * time.Minute
	}
	if o.Queue <= 0 {
		o.Queue = 4096
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Client == nil {
		o.Client = newClient()
	}
	if o.now == nil {
		o.now = time.Now
	}
	if o.FactsVersion == nil {
		o.FactsVersion = func() int { return 0 }
	}

	if err := os.MkdirAll(o.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("aggregate state directory: %w", err)
	}
	box, err := openOutbox(filepath.Join(o.Dir, "outbox"), OutboxLimit, o.Log)
	if err != nil {
		return nil, err
	}

	a := &Aggregator{
		o:       o,
		queue:   make(chan facts.Request, o.Queue),
		outbox:  box,
		windows: make(map[time.Time]*window),
		sender: &sender{
			url: o.URL, token: o.Token, node: o.NodeID, version: o.Version,
			client: o.Client, outbox: box, log: o.Log,
			wake: make(chan struct{}, 1),
		},
	}
	a.load()
	return a, nil
}

// Write puts an event into the queue and returns at once. It satisfies
// proxy.EventLog.
func (a *Aggregator) Write(r facts.Request) {
	select {
	case a.queue <- r:
	default:
		a.Dropped.Add(1)
	}
}

// Status is what the service port shows.
type Status struct {
	Dropped int64 `json:"dropped"`
	Outbox  int   `json:"outbox"`
}

func (a *Aggregator) Status() Status {
	ids, _ := a.outbox.list()
	return Status{Dropped: a.Dropped.Load(), Outbox: len(ids)}
}

// Run counts, closes, packs and sends until the context ends, then
// saves the open windows so that the next start carries on from them.
func (a *Aggregator) Run(ctx context.Context) {
	sendCtx, stopSending := context.WithCancel(ctx)
	sent := make(chan struct{})
	go func() {
		a.sender.run(sendCtx)
		close(sent)
	}()
	defer func() {
		stopSending()
		<-sent
	}()

	now := a.o.now()
	// The first batch comes after a random part of the interval: every
	// installation started from one image would otherwise post at the
	// same second, every fifteen minutes, forever.
	nextFlush := now.Add(a.o.Interval/2 + time.Duration(rand.Int63n(int64(a.o.Interval)/2+1)))
	nextSave := now.Add(saveEvery)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()

	for {
		select {
		case r := <-a.queue:
			a.add(r)

		case <-tick.C:
			now := a.o.now()
			a.closeWindows(now)
			if !now.Before(nextFlush) {
				a.flush(now)
				nextFlush = now.Add(a.o.Interval)
			}
			if !now.Before(nextSave) {
				a.save()
				nextSave = now.Add(saveEvery)
			}

		case <-ctx.Done():
			// What is already queued is counted: those visitors were
			// served, and a stop is no reason to forget them.
			for {
				select {
				case r := <-a.queue:
					a.add(r)
					continue
				default:
				}
				break
			}
			a.save()
			return
		}
	}
}

// add counts one event into its window.
//
// The window is chosen by the moment the request finished, not the one
// it began: a long download counted into a window that has already
// closed would have nowhere to go. A late one still lands in the oldest
// open window rather than reopening a closed one — a window that went
// out must not change.
func (a *Aggregator) add(r facts.Request) {
	t := r.Time.Add(r.Duration)
	if r.Time.IsZero() {
		t = a.o.now()
	}
	start := t.UTC().Truncate(WindowLength)
	if start.Before(a.openFrom) {
		start = a.openFrom
	}

	w, ok := a.windows[start]
	if !ok {
		w = newWindow(start)
		a.windows[start] = w
	}
	w.add(keyOf(&r, a.o.Served), &r)
}

// closeWindows closes every window that ended more than grace ago.
func (a *Aggregator) closeWindows(now time.Time) {
	edge := now.Add(-grace).UTC().Truncate(WindowLength)
	if edge.After(a.openFrom) {
		a.openFrom = edge
	}

	closed := false
	for start, w := range a.windows {
		if !start.Before(a.openFrom) {
			continue
		}
		if rows := w.close(); len(rows) > 0 {
			a.pending = append(a.pending, closedWindow{
				Start: start, Facts: a.o.FactsVersion(), Rows: rows,
			})
		}
		delete(a.windows, start)
		closed = true
	}
	if closed {
		sort.Slice(a.pending, func(i, j int) bool {
			return a.pending[i].Start.Before(a.pending[j].Start)
		})
	}
}

// flush packs the closed windows into batches and puts them into the
// outbox.
//
// A window is never split between batches, and a batch never holds
// more than MaxRows rows — the schema caps the batch, not the window,
// and three full windows in one batch would be refused whole. A batch
// also holds one fact set version only, since it names one.
func (a *Aggregator) flush(now time.Time) {
	if len(a.pending) == 0 {
		return
	}

	var batches []*Batch
	for _, cw := range a.pending {
		cur := (*Batch)(nil)
		if n := len(batches); n > 0 {
			cur = batches[n-1]
		}
		if cur == nil || len(cur.Rows)+len(cw.Rows) > MaxRows || cur.FactsVersion != cw.Facts {
			cur = &Batch{
				Format:       FormatVersion,
				Batch:        batchID(a.o.NodeID, cw.Start),
				Node:         a.o.NodeID,
				NodeVersion:  a.o.Version,
				FactsVersion: cw.Facts,
				SentAt:       now.UTC().Format(time.RFC3339),
			}
			batches = append(batches, cur)
		}
		cur.Rows = append(cur.Rows, cw.Rows...)
	}

	done := 0
	for _, b := range batches {
		body, err := encodeBatch(b)
		if err == nil {
			err = a.outbox.put(b.Batch, body)
		}
		if err != nil {
			// The windows stay pending and are packed again next time:
			// a disk that failed once may not fail twice.
			a.o.Log.Error("a batch was not written to the outbox", "batch", b.Batch, "err", err)
			break
		}
		done += len(b.Rows)
	}

	// Drop exactly the windows whose rows made it to disk.
	for done > 0 && len(a.pending) > 0 {
		done -= len(a.pending[0].Rows)
		a.pending = a.pending[1:]
	}
	if len(a.pending) == 0 {
		a.pending = nil
	}

	// Saved at once: a crash between the outbox and the state would
	// otherwise pack the same windows again. Even then nothing is
	// counted twice — the batch key is derived from the windows, so the
	// repeat carries the same key.
	a.save()

	select {
	case a.sender.wake <- struct{}{}:
	default:
	}
}

// batchID derives the batch key from the node and the first window.
//
// Derived rather than random on purpose: a batch assembled again after
// a crash carries the same key, and the cloud, which drops repeated
// keys, does not count it twice. A window belongs to exactly one batch,
// so two batches of one node never share a first window.
func batchID(node string, first time.Time) string {
	return node + "-" + first.UTC().Format("20060102T1504Z")
}

func encodeBatch(b *Batch) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// snapshot is what survives a restart.
type snapshot struct {
	Format   int            `json:"format"`
	OpenFrom time.Time      `json:"open_from"`
	Windows  []savedWindow  `json:"windows"`
	Pending  []closedWindow `json:"pending"`
}

type savedWindow struct {
	Start    time.Time  `json:"start"`
	Rows     []savedRow `json:"rows"`
	Overflow *counts    `json:"overflow,omitempty"`
}

type savedRow struct {
	Key    Key     `json:"key"`
	Counts *counts `json:"counts"`
}

func (a *Aggregator) save() {
	s := snapshot{Format: FormatVersion, OpenFrom: a.openFrom, Pending: a.pending}
	for start, w := range a.windows {
		sw := savedWindow{Start: start, Overflow: w.overflow}
		for k, c := range w.rows {
			sw.Rows = append(sw.Rows, savedRow{Key: k, Counts: c})
		}
		s.Windows = append(s.Windows, sw)
	}

	raw, err := json.Marshal(s)
	if err == nil {
		err = writeFileAtomic(filepath.Join(a.o.Dir, stateFile), raw, 0o640)
	}
	if err != nil {
		a.o.Log.Error("the open aggregate window was not saved", "err", err)
	}
}

// load restores the previous run. A broken file is moved aside rather
// than repaired: the counts in it are lost either way, and the file is
// kept for whoever wants to know why.
func (a *Aggregator) load() {
	path := filepath.Join(a.o.Dir, stateFile)
	s, err := readSnapshot(path)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		a.o.Log.Error("the saved aggregate window is unreadable and is set aside; "+
			"counting starts afresh", "file", path, "err", err)
		os.Rename(path, path+".broken")
		return
	}

	a.openFrom = s.OpenFrom
	a.pending = s.Pending
	for _, sw := range s.Windows {
		w := newWindow(sw.Start)
		w.overflow = sw.Overflow
		for _, r := range sw.Rows {
			if r.Counts != nil {
				w.rows[r.Key] = r.Counts
			}
		}
		a.windows[sw.Start] = w
	}
}

func readSnapshot(path string) (snapshot, error) {
	var s snapshot
	raw, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, err
	}
	if s.Format != FormatVersion {
		return s, fmt.Errorf("state format %d, this node understands %d", s.Format, FormatVersion)
	}
	return s, nil
}

// WindowSummary describes a window for the antibot aggregate command.
type WindowSummary struct {
	Start    time.Time
	Rows     int
	Requests uint64
}

// State is what lies in a state directory besides the outbox.
type State struct {
	Open    []WindowSummary
	Pending []WindowSummary
}

// ReadState summarizes the state directory without starting anything.
func ReadState(dir string) (State, error) {
	var st State
	s, err := readSnapshot(filepath.Join(dir, stateFile))
	if errors.Is(err, fs.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	for _, w := range s.Windows {
		sum := WindowSummary{Start: w.Start, Rows: len(w.Rows)}
		for _, r := range w.Rows {
			if r.Counts != nil {
				sum.Requests += r.Counts.Requests
			}
		}
		if w.Overflow != nil {
			sum.Requests += w.Overflow.Requests
		}
		st.Open = append(st.Open, sum)
	}
	for _, w := range s.Pending {
		sum := WindowSummary{Start: w.Start, Rows: len(w.Rows)}
		for _, r := range w.Rows {
			sum.Requests += r.Requests
		}
		st.Pending = append(st.Pending, sum)
	}
	sort.Slice(st.Open, func(i, j int) bool { return st.Open[i].Start.Before(st.Open[j].Start) })
	return st, nil
}
