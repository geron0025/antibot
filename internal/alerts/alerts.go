// Package alerts tells the node's owner that something is wrong with the
// site — without waiting for the owner to open the admin UI.
//
// A trigger only tells. It changes neither the rules nor their mode,
// nothing about the protection at all: a human decides.
//
// The node does not deliver the message itself. It runs the owner's
// command — a curl to Telegram, to a webhook, to a mail server — and
// hands it the message in environment variables and as JSON on stdin,
// never pasted into the command's text: a visitor's User-Agent must not
// become code in the owner's shell. The node keeps no mail client and no
// bot of its own: those would be outside dependencies and somebody's
// credentials inside the node.
//
// The traffic is counted on the hot path, by the minute, in memory. The
// log summary is for the admin UI; a trigger has to fire within a minute
// rather than after a reread of the log.
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/i18n"
	"github.com/geron0025/antibot/internal/summary"
)

// Kinds of trigger. An alert's id is its kind, or the kind and what it is
// about: "rule_spike:block-hosting".
const (
	SiteDown      = "site_down"
	RuleSpike     = "rule_spike"
	RequestsSpike = "requests_spike"
	BlockedSpike  = "blocked_spike"
	CertExpiring  = "cert_expiring"
	EventsDropped = "events_dropped"
	DiskLow       = "disk_low"
	FactsStale    = "facts_stale"
	OutboxStuck   = "outbox_stuck"
)

// States of a message.
const (
	Firing   = "firing"
	Resolved = "resolved"
	Test     = "test"
)

// Alert is one message as the owner's command receives it.
type Alert struct {
	ID    string    `json:"id"`
	Kind  string    `json:"kind"`
	State string    `json:"state"`
	Text  string    `json:"text"`
	Host  string    `json:"host"`
	Time  time.Time `json:"time"`

	// Language is the one Text is in; Message is Text as a key and its
	// arguments, for whoever words it anew.
	Language i18n.Lang `json:"language"`
	Message  Message   `json:"message"`
}

// Certificate is what the certificate check needs to know of one.
type Certificate struct {
	Names    []string
	NotAfter time.Time
}

// Probes read the node's state for the checks that are not about the
// traffic. Any of them may be nil: that check is then off.
type Probes struct {
	Certificates  func() []Certificate
	EventsDropped func() int64

	// EventsDir is where the log lives; its disk is the one watched.
	EventsDir string

	// Facts is the applied fact set — its version and when it was built —
	// and whether the node fetches sets at all.
	Facts func() (version int, built time.Time, fetching bool)

	// Outbox is how many aggregate batches wait to be sent; ok is false
	// when the node sends none.
	Outbox func() (pending int, ok bool)
}

// Options are the thresholds; the configuration gives the defaults.
type Options struct {
	Window time.Duration

	SiteErrorShare  float64
	SiteMinRequests int

	SpikeFactor      float64
	SpikeMinRequests int
	SpikeMinBlocked  int
	RuleMinMatches   int

	CertDays     int
	DiskMinBytes uint64
	FactsMaxAge  time.Duration
	OutboxMax    int

	Probes Probes

	// Command is the owner's command in force right now. Empty means the
	// alerts are only written to the node's log and shown in the admin UI.
	Command func() string
	Timeout time.Duration

	// Language is the one the messages are worded in for the command,
	// read at every message: a change takes effect with the next one.
	// Nil or empty is English.
	Language func() i18n.Lang

	Log *slog.Logger
}

const (
	// ringMinutes covers the longest window plus the hour it is compared
	// with.
	ringMinutes = 2 * 60

	// baselineMinutes is the stretch before the window that "many times
	// more than usual" is measured against. The hour before rather than
	// the same hour yesterday: a restart would lose yesterday, and a
	// sudden spike is what an attack looks like, while the morning rise
	// of a site takes longer than an hour.
	baselineMinutes = 60

	// baselineNeeded is how much of that hour has to be counted before a
	// spike means anything: right after a start the usual is unknown, and
	// every busy site would look like an attack.
	baselineNeeded = 30

	historySize = 100
	queueSize   = 64
)

type minute struct {
	stamp    int64
	requests int
	blocked  int
	reached  int
	failed   int
	rules    map[string]int
}

// Watcher counts the traffic, checks the triggers once a minute and
// hands what fires to the owner's command.
type Watcher struct {
	o       Options
	host    string
	started time.Time

	mu   sync.Mutex
	ring [ringMinutes]minute

	stateMu   sync.Mutex
	states    map[string]*state
	history   []*Entry
	dropped   int64
	droppedAt time.Time

	queue chan job
}

type state struct {
	kind string
	msg  Message
	// first is what the trigger fired with, the one "back to normal"
	// recalls; msg follows the latest check, for the page and the bell.
	first      Message
	since      time.Time
	clearSince time.Time
}

// Entry is a message in the history: what was said and what became of
// its delivery.
type Entry struct {
	Alert
	Delivery string
}

// Status is a trigger that is firing now.
type Status struct {
	ID, Kind, Text string
	Message        Message
	Since          time.Time

	// Clearing says the condition is gone and the node waits a window
	// before saying "back to normal": a flapping trigger must not send a
	// message a minute.
	Clearing bool
}

type job struct {
	alert Alert
	entry *Entry
}

type finding struct {
	kind string
	msg  Message
}

// New assembles a watcher; Run starts it.
func New(o Options) *Watcher {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Window < time.Minute {
		o.Window = 5 * time.Minute
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	host, _ := os.Hostname()
	return &Watcher{
		o: o, host: host, started: time.Now(),
		states: map[string]*state{},
		queue:  make(chan job, queueSize),
	}
}

// Write counts a request. It is the hot path's: a lock and a few
// additions, nothing more.
func (w *Watcher) Write(r facts.Request) {
	at := r.Time
	if at.IsZero() {
		at = time.Now()
	}
	m := at.Unix() / 60

	w.mu.Lock()
	defer w.mu.Unlock()
	slot := &w.ring[m%ringMinutes]
	if slot.stamp > m {
		// An event older than the ring remembers; it would overwrite a
		// newer minute.
		return
	}
	if slot.stamp != m {
		*slot = minute{stamp: m}
	}
	slot.requests++
	switch summary.AnswerOf(&r) {
	case summary.AnswerBlocked:
		slot.blocked++
		if r.Rule != "" {
			if slot.rules == nil {
				slot.rules = map[string]int{}
			}
			slot.rules[r.Rule]++
		}
	case summary.AnswerServerError:
		slot.reached++
		slot.failed++
	case summary.AnswerNone:
	default:
		slot.reached++
	}
}

// Run checks the triggers once a minute and delivers what fires, for as
// long as the context lives.
func (w *Watcher) Run(ctx context.Context) {
	go w.deliverAll(ctx)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			w.Check(now)
		}
	}
}

// Check looks at every trigger once. Exported for the tests, which need
// a clock of their own.
func (w *Watcher) Check(now time.Time) {
	found := map[string]finding{}
	add := func(id, kind string, msg Message) { found[id] = finding{kind, msg} }
	w.traffic(now, add)
	w.node(now, add)
	w.transition(now, found)
}

func (w *Watcher) sum(from, to int64) minute {
	total := minute{rules: map[string]int{}}
	w.mu.Lock()
	defer w.mu.Unlock()
	for m := from; m < to; m++ {
		s := &w.ring[m%ringMinutes]
		if s.stamp != m {
			continue
		}
		total.requests += s.requests
		total.blocked += s.blocked
		total.reached += s.reached
		total.failed += s.failed
		for id, n := range s.rules {
			total.rules[id] += n
		}
	}
	return total
}

func (w *Watcher) traffic(now time.Time, add func(id, kind string, msg Message)) {
	win := int64(w.o.Window / time.Minute)
	// The minute under way is left out: it is only partly counted.
	end := now.Unix() / 60
	cur := w.sum(end-win, end)
	over := seconds(w.o.Window)

	if cur.reached >= w.o.SiteMinRequests && cur.reached > 0 &&
		float64(cur.failed) >= w.o.SiteErrorShare*float64(cur.reached) {
		add(SiteDown, SiteDown, message("alert.site_down",
			number(int64(cur.failed)), number(int64(cur.reached)), over))
	}

	covered := int64(now.Sub(w.started)/time.Minute) - win
	if covered > baselineMinutes {
		covered = baselineMinutes
	}
	if covered < baselineNeeded {
		return
	}
	base := w.sum(end-win-covered, end-win)
	usual := func(n int) float64 { return float64(n) * float64(win) / float64(covered) }
	rounded := func(f float64) Arg { return number(int64(math.RoundToEven(f))) }
	spike := func(n int, usual float64, least int) bool {
		return n >= least && float64(n) >= w.o.SpikeFactor*usual
	}

	if u := usual(base.requests); spike(cur.requests, u, w.o.SpikeMinRequests) {
		add(RequestsSpike, RequestsSpike, message("alert.requests_spike",
			number(int64(cur.requests)), over, rounded(u)))
	}
	if u := usual(base.blocked); spike(cur.blocked, u, w.o.SpikeMinBlocked) {
		add(BlockedSpike, BlockedSpike, message("alert.blocked_spike",
			number(int64(cur.blocked)), over, rounded(u)))
	}
	for id, n := range cur.rules {
		if u := usual(base.rules[id]); spike(n, u, w.o.RuleMinMatches) {
			add(RuleSpike+":"+id, RuleSpike, message("alert.rule_spike",
				text(id), number(int64(n)), over, rounded(u)))
		}
	}
}

func (w *Watcher) node(now time.Time, add func(id, kind string, msg Message)) {
	p := w.o.Probes

	if p.Certificates != nil && w.o.CertDays > 0 {
		for _, c := range p.Certificates() {
			left := c.NotAfter.Sub(now)
			if left >= time.Duration(w.o.CertDays)*24*time.Hour || len(c.Names) == 0 {
				continue
			}
			names := strings.Join(c.Names, ", ")
			msg := message("alert.cert_expiring", text(names), date(c.NotAfter), number(int64(left.Hours()/24)))
			if left <= 0 {
				msg = message("alert.cert_expired", text(names), date(c.NotAfter))
			}
			add(CertExpiring+":"+c.Names[0], CertExpiring, msg)
		}
	}

	if p.EventsDropped != nil {
		n := p.EventsDropped()
		w.stateMu.Lock()
		if n > w.dropped {
			w.dropped, w.droppedAt = n, now
		}
		recent := !w.droppedAt.IsZero() && now.Sub(w.droppedAt) < w.o.Window
		w.stateMu.Unlock()
		if recent {
			add(EventsDropped, EventsDropped, message("alert.events_dropped", number(n)))
		}
	}

	if p.EventsDir != "" && w.o.DiskMinBytes > 0 {
		if free, err := freeBytes(p.EventsDir); err == nil && free < w.o.DiskMinBytes {
			add(DiskLow, DiskLow, message("alert.disk_low", number(int64(free>>20)), text(p.EventsDir)))
		}
	}

	if p.Facts != nil && w.o.FactsMaxAge > 0 {
		version, built, fetching := p.Facts()
		switch {
		case !fetching:
		case version == 0 && now.Sub(w.started) >= w.o.FactsMaxAge:
			add(FactsStale, FactsStale, message("alert.facts_none", seconds(now.Sub(w.started))))
		case version > 0 && now.Sub(built) >= w.o.FactsMaxAge:
			add(FactsStale, FactsStale, message("alert.facts_stale",
				number(int64(now.Sub(built).Hours()/24)), text(strconv.Itoa(version))))
		}
	}

	if p.Outbox != nil && w.o.OutboxMax > 0 {
		if n, ok := p.Outbox(); ok && n >= w.o.OutboxMax {
			add(OutboxStuck, OutboxStuck, message("alert.outbox_stuck", number(int64(n))))
		}
	}
}

// transition turns findings into messages: one when a trigger fires,
// one when it has stayed clear for a whole window.
func (w *Watcher) transition(now time.Time, found map[string]finding) {
	w.stateMu.Lock()
	var out []*Entry

	ids := make([]string, 0, len(found))
	for id := range found {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		f := found[id]
		if st, ok := w.states[id]; ok {
			st.msg, st.clearSince = f.msg, time.Time{}
			continue
		}
		w.states[id] = &state{kind: f.kind, msg: f.msg, first: f.msg, since: now}
		out = append(out, w.recordLocked(w.alert(id, f.kind, Firing, f.msg, now)))
	}

	ids = ids[:0]
	for id := range w.states {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if _, ok := found[id]; ok {
			continue
		}
		st := w.states[id]
		if st.clearSince.IsZero() {
			st.clearSince = now
			continue
		}
		// Checks come once a minute off a ticker and drift by milliseconds:
		// without rounding, a window of quiet can fall a hair short and
		// "back to normal" waits a whole extra check.
		if now.Sub(st.clearSince).Round(time.Minute) < w.o.Window {
			continue
		}
		delete(w.states, id)
		out = append(out, w.recordLocked(w.alert(id, st.kind, Resolved, resolved(st, now), now)))
	}
	w.stateMu.Unlock()

	for _, e := range out {
		w.logAlert(e.Alert)
		w.enqueue(e)
	}
}

// alert is a message worded in the delivery language, as the command and
// the log get it.
func (w *Watcher) alert(id, kind, state string, msg Message, now time.Time) Alert {
	lang := w.lang()
	return Alert{ID: id, Kind: kind, State: state, Text: msg.In(lang), Host: w.host, Time: now,
		Language: lang, Message: msg}
}

func (w *Watcher) recordLocked(a Alert) *Entry {
	e := &Entry{Alert: a, Delivery: "waiting"}
	w.history = append(w.history, e)
	if len(w.history) > historySize {
		w.history = w.history[len(w.history)-historySize:]
	}
	return e
}

func (w *Watcher) logAlert(a Alert) {
	switch a.State {
	case Firing:
		w.o.Log.Warn("an alert is firing", "alert", a.ID, "text", a.Text)
	default:
		w.o.Log.Info("an alert", "alert", a.ID, "state", a.State, "text", a.Text)
	}
}

func (w *Watcher) enqueue(e *Entry) {
	select {
	case w.queue <- job{alert: e.Alert, entry: e}:
	default:
		w.o.Log.Error("an alert was not handed to the command: too many at once", "alert", e.ID)
		w.setDelivery(e, "not sent: too many messages at once")
	}
}

func (w *Watcher) deliverAll(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-w.queue:
			w.setDelivery(j.entry, w.run(ctx, j.alert))
		}
	}
}

func (w *Watcher) setDelivery(e *Entry, result string) {
	w.stateMu.Lock()
	e.Delivery = result
	w.stateMu.Unlock()
}

// Test runs the command with a test message and says what came of it.
func (w *Watcher) Test(ctx context.Context) string {
	a := w.alert(Test, Test, Test, message("alert.test", text(w.host)), time.Now())
	w.stateMu.Lock()
	e := w.recordLocked(a)
	w.stateMu.Unlock()
	w.logAlert(a)
	result := w.run(ctx, a)
	w.setDelivery(e, result)
	return result
}

// Firing lists the triggers firing now, the oldest first.
func (w *Watcher) Firing() []Status {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	out := make([]Status, 0, len(w.states))
	lang := w.lang()
	for id, st := range w.states {
		out = append(out, Status{ID: id, Kind: st.kind, Text: st.msg.In(lang), Message: st.msg, Since: st.since,
			Clearing: !st.clearSince.IsZero()})
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Since.Equal(out[j].Since) {
			return out[i].Since.Before(out[j].Since)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// History is the messages since the start, the newest first.
func (w *Watcher) History() []Entry {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()
	out := make([]Entry, 0, len(w.history))
	for i := len(w.history) - 1; i >= 0; i-- {
		out = append(out, *w.history[i])
	}
	return out
}

// Trigger describes a check for the admin UI: what it watches and when
// it fires, with the thresholds in force.
type Trigger struct {
	Kind, Title, When string

	// Args are the thresholds of When as bare numbers, for an admin UI
	// that words the condition in its viewer's language: percentages as
	// whole percents, spans in seconds, sizes in megabytes, in the order
	// they appear in the English When.
	Args []int64 `json:",omitempty"`
}

// Triggers lists the checks in the order the page shows them.
func (w *Watcher) Triggers() []Trigger {
	o, over := w.o, span(w.o.Window)
	window := int64(w.o.Window / time.Second)
	factor := int64(math.Round(o.SpikeFactor))
	return []Trigger{
		{SiteDown, "the site does not answer", fmt.Sprintf(
			"a 5xx of the site in %.0f%% of at least %d requests that reached it, over %s",
			100*o.SiteErrorShare, o.SiteMinRequests, over),
			[]int64{int64(math.Round(100 * o.SiteErrorShare)), int64(o.SiteMinRequests), window}},
		{RuleSpike, "a rule cuts off a lot", fmt.Sprintf(
			"at least %d cut off by one rule over %s, and %.0f times its usual over the hour before",
			o.RuleMinMatches, over, o.SpikeFactor),
			[]int64{int64(o.RuleMinMatches), window, factor}},
		{RequestsSpike, "a spike of requests", fmt.Sprintf(
			"at least %d over %s, and %.0f times the usual over the hour before",
			o.SpikeMinRequests, over, o.SpikeFactor),
			[]int64{int64(o.SpikeMinRequests), window, factor}},
		{BlockedSpike, "a spike of cut-off requests", fmt.Sprintf(
			"at least %d over %s, and %.0f times the usual over the hour before",
			o.SpikeMinBlocked, over, o.SpikeFactor),
			[]int64{int64(o.SpikeMinBlocked), window, factor}},
		{CertExpiring, "a certificate expires", fmt.Sprintf("%d days before the end of its term", o.CertDays),
			[]int64{int64(o.CertDays)}},
		{EventsDropped, "the log loses events", fmt.Sprintf("its queue overflowed within %s", over),
			[]int64{window}},
		{DiskLow, "the disk runs out", fmt.Sprintf("less than %d MB free under the event log", o.DiskMinBytes>>20),
			[]int64{int64(o.DiskMinBytes >> 20)}},
		{FactsStale, "the fact set is stale", fmt.Sprintf(
			"no new set for %s while the node fetches them", span(o.FactsMaxAge)),
			[]int64{int64(o.FactsMaxAge / time.Second)}},
		{OutboxStuck, "aggregates do not leave", fmt.Sprintf("%d batches waiting to be sent", o.OutboxMax),
			[]int64{int64(o.OutboxMax)}},
	}
}

// resolved says what is over, how long it lasted and how long it has
// been clear, and recalls what the trigger fired with. The latest
// message is not used: it is worded as the present, and by the end it
// mixes the trouble with the calm after it.
func resolved(st *state, now time.Time) Message {
	return message("alert.resolved", trigger(st.kind),
		seconds(st.clearSince.Sub(st.since)), seconds(now.Sub(st.clearSince)), nested(st.first))
}

func span(d time.Duration) string {
	switch {
	case d < time.Minute:
		return "under a minute"
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= time.Hour:
		d = d.Round(time.Minute)
		if d%time.Hour == 0 {
			return fmt.Sprintf("%dh", int(d.Hours()))
		}
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	}
}
