package alerts

import (
	"embed"
	"fmt"
	"io/fs"
	"slices"
	"sync"
	"time"

	"github.com/geron0025/antibot/internal/i18n"
)

// The alerts speak the languages of the admin UI. The core words each
// message in the delivery language for the owner's command; the admin UI
// words the same message again in the language of whoever looks at it.
// Both take the words from the catalog here, so the two never disagree.

//go:embed locales/*.json
var localesFS embed.FS

// Message is the text of an alert as a key of the catalog and its
// arguments.
type Message struct {
	Key  string `json:"key"`
	Args []Arg  `json:"args,omitempty"`
}

// Arg is one argument of a message; exactly one of its fields is set.
type Arg struct {
	Text    string     `json:"text,omitempty"`
	Number  *int64     `json:"number,omitempty"`
	Seconds *int64     `json:"seconds,omitempty"`
	Date    *time.Time `json:"date,omitempty"`
	// Trigger is a trigger's kind, worded as its title.
	Trigger string `json:"trigger,omitempty"`
	// Message is a message inside a message: what fired, recalled when
	// it is over.
	Message *Message `json:"message,omitempty"`
}

func text(s string) Arg           { return Arg{Text: s} }
func number(n int64) Arg          { return Arg{Number: &n} }
func seconds(d time.Duration) Arg { s := int64(d / time.Second); return Arg{Seconds: &s} }
func date(t time.Time) Arg        { return Arg{Date: &t} }
func trigger(kind string) Arg     { return Arg{Trigger: kind} }
func nested(m Message) Arg        { return Arg{Message: &m} }

func message(key string, args ...Arg) Message { return Message{Key: key, Args: args} }

var catalog = sync.OnceValues(func() (*i18n.Catalog, error) {
	sub, err := fs.Sub(localesFS, "locales")
	if err != nil {
		return nil, err
	}
	c, err := i18n.Load(sub, i18n.EN)
	if err != nil {
		return nil, fmt.Errorf("the alerts' translations: %w", err)
	}
	return c, nil
})

// Catalog is the alerts' messages in every language.
func Catalog() (*i18n.Catalog, error) { return catalog() }

// printer is the catalog in a language; nil when the catalog is broken,
// which the tests do not let into a build.
func printer(lang i18n.Lang) *i18n.Printer {
	c, err := catalog()
	if err != nil {
		return nil
	}
	return c.Printer(lang)
}

// In words the message in a language. A broken catalog or an unknown key
// shows the key: a message must never vanish for want of its words.
func (m Message) In(lang i18n.Lang) string {
	p := printer(lang)
	if p == nil {
		return m.Key
	}
	return m.word(p)
}

func (m Message) word(p *i18n.Printer) string {
	args := make([]any, len(m.Args))
	for i, a := range m.Args {
		args[i] = a.word(p)
	}
	return p.T(m.Key, args...)
}

func (a Arg) word(p *i18n.Printer) any {
	switch {
	case a.Message != nil:
		return a.Message.word(p)
	case a.Number != nil:
		return *a.Number
	case a.Seconds != nil:
		return Span(p, *a.Seconds)
	case a.Date != nil:
		return p.Date(*a.Date)
	case a.Trigger != "":
		if t, ok := triggerTexts[a.Trigger]; ok {
			return p.T(t.title)
		}
		return a.Trigger
	default:
		return a.Text
	}
}

// triggerTexts are each trigger's words in the catalog: its title, and
// its condition built from Trigger.Args. spans are the positions of the
// arguments that are seconds.
var triggerTexts = map[string]struct {
	title, when string
	args        int
	spans       []int
}{
	SiteDown:      {"trigger.site_down", "trigger.site_down_when", 3, []int{2}},
	RuleSpike:     {"trigger.rule_spike", "trigger.rule_spike_when", 3, []int{1}},
	RequestsSpike: {"trigger.requests_spike", "trigger.requests_spike_when", 3, []int{1}},
	BlockedSpike:  {"trigger.blocked_spike", "trigger.blocked_spike_when", 3, []int{1}},
	CertExpiring:  {"trigger.cert_expiring", "trigger.cert_expiring_when", 1, nil},
	EventsDropped: {"trigger.events_dropped", "trigger.events_dropped_when", 1, []int{0}},
	DiskLow:       {"trigger.disk_low", "trigger.disk_low_when", 1, nil},
	FactsStale:    {"trigger.facts_stale", "trigger.facts_stale_when", 1, []int{0}},
	OutboxStuck:   {"trigger.outbox_stuck", "trigger.outbox_stuck_when", 1, nil},
}

// In words the trigger's title, and its condition when the core sent the
// numbers, in a language. A kind the catalog does not know, or a core
// too old to send the numbers, keeps the core's own words.
func (t Trigger) In(lang i18n.Lang) Trigger {
	text, ok := triggerTexts[t.Kind]
	p := printer(lang)
	if !ok || p == nil {
		return t
	}
	t.Title = p.T(text.title)
	if len(t.Args) != text.args {
		return t
	}
	args := make([]any, len(t.Args))
	for i, v := range t.Args {
		if slices.Contains(text.spans, i) {
			args[i] = Span(p, v)
		} else {
			args[i] = v
		}
	}
	t.When = p.T(text.when, args...)
	return t
}

// Span words a duration given in seconds the way the thresholds are
// worded: whole minutes, hours, days.
func Span(p *i18n.Printer, secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d < time.Minute:
		return p.T("span.under_a_minute")
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return p.N("span.days", int(d.Hours()/24))
	case d >= time.Hour:
		d = d.Round(time.Minute)
		if d%time.Hour == 0 {
			return p.T("span.hours", int(d.Hours()))
		}
		return p.T("span.hours_minutes", int(d.Hours()), fmt.Sprintf("%02d", int(d.Minutes())%60))
	default:
		return p.T("span.minutes", int(d.Round(time.Minute).Minutes()))
	}
}

// lang is the delivery language now: the one the options name, when the
// node speaks it, and English otherwise.
func (w *Watcher) lang() i18n.Lang {
	if w.o.Language == nil {
		return i18n.EN
	}
	if l, ok := i18n.Parse(string(w.o.Language())); ok {
		return l
	}
	return i18n.EN
}
