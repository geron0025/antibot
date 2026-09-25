package admin

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/geron0025/antibot/internal/events"
	"github.com/geron0025/antibot/internal/facts"
	"github.com/geron0025/antibot/internal/rules"
	"github.com/geron0025/antibot/internal/summary"
)

type rulePageData struct {
	pageCommon
	CSRF string

	Rule    rules.Rule
	Enabled bool
	JSON    string

	// Summary counts only the requests the rule touched — decided or
	// marked in shadow; Summary.Total is all the requests of the period.
	Summary *summary.Summary
	Series  *columnsChart
	Events  []facts.Request

	// ExportPeriod is the period as the download reads it.
	ExportPeriod string
}

// rulePage is one rule: what it is, how often it fired and when, and whom
// it touched. It is what a move to active is decided by — the list of
// rules gives a number, this page gives the addresses, the fingerprints
// and the paths behind it.
//
// The rule is named in the query rather than the path: an id is the
// owner's text and may hold a slash.
func (s *Server) rulePage(w http.ResponseWriter, r *http.Request, user string) {
	id := r.URL.Query().Get("id")
	if s.o.Rules == nil {
		http.Redirect(w, r, "/rules", http.StatusSeeOther)
		return
	}
	set := s.o.Rules.Set()
	var rule *rules.Rule
	for _, candidate := range set.All() {
		if candidate.ID == id {
			found := candidate
			rule = &found
		}
	}
	if rule == nil {
		http.Redirect(w, r, withError("/rules", s.t(r, "rule.no_such", strconv.Quote(id))), http.StatusSeeOther)
		return
	}
	enabled := false
	for _, effective := range set.Effective() {
		if effective.ID == id {
			enabled = true
		}
	}
	written, _ := json.MarshalIndent(rule, "", "  ")

	period := periodOf(r)
	now := time.Now()
	data := rulePageData{
		pageCommon:   s.common(r, user, "rules", period, r.URL.Query().Get("error")),
		CSRF:         s.csrfToken(r),
		Rule:         *rule,
		Enabled:      enabled,
		JSON:         string(written),
		ExportPeriod: period.String(),
	}

	f := summary.Filter{Rule: id}
	result, err := summary.Build(summary.Options{
		Dir: s.o.EventsDir, From: now.Add(-period), To: now,
		Buckets: bucketsFor(period), Filter: &f,
	})
	if err != nil {
		data.Error = err.Error()
		data.Summary = &summary.Summary{Decisions: map[string]int{}}
	} else {
		data.Summary = result
		if result.Events > 0 {
			data.Series = newColumns(s.printer(r), result.Series, period)
		}
	}
	if list, err := summary.Latest(s.o.EventsDir, f, 20); err == nil {
		data.Events = list
	}
	s.render(w, r, "rule.html", data)
}

// exportLimit bounds a download. A day of a busy site is hundreds of
// thousands of lines; the log on disk stays the place for all of it.
const exportLimit = 500_000

// exportEvents hands out the events matching the events page's filters
// over a period, as the log's own NDJSON lines, oldest first.
//
// The events carry the visitors' addresses, so every download lands in
// the node's log: who took how many, and from where.
func (s *Server) exportEvents(w http.ResponseWriter, r *http.Request, user string) {
	f := eventsFilter(r.URL.Query())
	period := periodOf(r)
	now := time.Now()

	name := fmt.Sprintf("antibot-events-%s.ndjson", now.Format("2006-01-02-1504"))
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	started := false
	n := 0
	_, err := events.Read(events.Filter{Dir: s.o.EventsDir, From: now.Add(-period), To: now},
		func(ev facts.Request) error {
			if !f.Matches(&ev) {
				return nil
			}
			if n >= exportLimit {
				return events.ErrStop
			}
			if !started {
				w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
				started = true
			}
			n++
			return enc.Encode(ev)
		})
	switch {
	case err != nil && !started:
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	case err != nil:
		s.o.Log.Error("the events export broke off", "who", user, "events", n, "err", err)
	case !started:
		// Nothing matched: an empty file is still a file, and the
		// browser must not show the empty answer as a page.
		w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	s.o.Log.Info("events were exported from the admin UI", "who", user, "events", n,
		"period", period.String(), "filter", url.Values(r.URL.Query()).Encode(), "address", clientAddr(r))
}
