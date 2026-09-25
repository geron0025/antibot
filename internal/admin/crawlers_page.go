package admin

import (
	"net/http"
	"slices"
	"time"

	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/crawlers"
	"github.com/geron0025/antibot/internal/summary"
)

type crawlersData struct {
	pageCommon
	CSRF string

	// Settings is nil when the admin UI has no file to keep them in: the
	// tab then shows the traffic but offers no switch.
	Settings *crawlers.Settings
	Report   *summary.Crawlers

	// Held are the owners held back that did not show up over the
	// period: they are listed anyway, or there would be no way back.
	Held []string
}

// crawlersPage is the tab of verified crawlers: networks the fact set
// names a crawler's and marks protected. They pass before the rules
// unless the owner decided otherwise — here, wholly or for one owner of
// networks. The cloud only says who is a verified crawler; what happens
// to them is the owner's.
func (s *Server) crawlersPage(w http.ResponseWriter, r *http.Request, user string) {
	period := periodOf(r)
	now := time.Now()
	data := crawlersData{
		pageCommon: s.common(r, user, "rules", period, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
	}
	data.Tab = "crawlers"
	if s.o.Crawlers != nil {
		// The file may have been edited by hand since the last look.
		if _, err := s.o.Crawlers.Reload(); err != nil {
			data.Error = err.Error()
		}
		st := s.o.Crawlers.Get()
		data.Settings = &st
	}

	report, err := summary.BuildCrawlers(s.o.EventsDir, now.Add(-period), now)
	if err != nil {
		data.Error = err.Error()
		report = &summary.Crawlers{}
	}
	data.Report = report
	if data.Settings != nil {
		for _, owner := range data.Settings.Held {
			seen := slices.ContainsFunc(report.Owners, func(o summary.CrawlerOwner) bool { return o.Owner == owner })
			if !seen {
				data.Held = append(data.Held, owner)
			}
		}
	}
	s.render(w, r, "crawlers.html", data)
}

// setCrawlers changes the pass. Turning it off, or holding an owner
// back, lets the rules reach a search engine: it asks for the password.
// Turning it on and letting an owner through again is a step towards
// safety and asks for nothing.
func (s *Server) setCrawlers(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	back := "/rules/crawlers"
	fail := func(m string) { http.Redirect(w, r, withError(back, m), http.StatusSeeOther) }
	if s.o.Crawlers == nil {
		fail(s.t(r, "crawlers.no_file"))
		return
	}

	if _, err := s.o.Crawlers.Reload(); err != nil {
		fail(err.Error())
		return
	}
	st := s.o.Crawlers.Get()
	owner := r.PostFormValue("owner")
	risky := false
	switch r.PostFormValue("do") {
	case "pass_off":
		st.Pass, risky = false, true
	case "pass_on":
		st.Pass = true
	case "hold":
		if owner == "" {
			fail(s.t(r, "error.invalid_form"))
			return
		}
		st.Held, risky = append(st.Held, owner), true
	case "release":
		st.Held = slices.DeleteFunc(st.Held, func(o string) bool { return o == owner })
	default:
		fail(s.t(r, "error.invalid_form"))
		return
	}
	if risky && !s.recheck(w, r, who, "hold verified crawlers back", fail) {
		return
	}
	if err := s.o.Crawlers.Save(st, who, time.Now()); err != nil {
		s.o.Log.Error("the verified crawlers' pass was not changed", "who", who, "err", err)
		fail(err.Error())
		return
	}
	s.reload(r.Context(), control.ReloadCrawlers)

	log := s.o.Log.Info
	if risky {
		log = s.o.Log.Warn
	}
	log("the verified crawlers' pass was changed from the admin UI",
		"do", r.PostFormValue("do"), "owner", owner, "pass", st.Pass, "held", st.Held,
		"who", who, "address", clientAddr(r))
	http.Redirect(w, r, back, http.StatusSeeOther)
}
