package admin

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/geron0025/antibot/internal/control"
	"github.com/geron0025/antibot/internal/proposals"
	"github.com/geron0025/antibot/internal/rules"
)

// maxReasonRunes mirrors internal/proposals's own limit: rather than let
// a reason travel all the way to Store.Reject and come back as the
// package's own English sentence, the tab enforces the same cap itself
// and says so in the owner's language, before either the proposal's
// state or the advice's is even looked at.
const maxReasonRunes = 500

// proposalView is one proposal ready for the template: the rule
// pretty-printed the way rule.html shows a rule's own JSON — the rules
// page renders no condition of its own to reuse.
type proposalView struct {
	proposals.Proposal
	RuleJSON string
}

// adviceView is one piece of advice together with the owner's own rule it
// names by hash — proposals.Store.List only ever returns advice whose
// hash still matches a rule in current, so RuleID is never empty here.
type adviceView struct {
	proposals.Advice
	RuleID   string
	RuleName string
}

type proposalsData struct {
	pageCommon
	CSRF string

	Proposals []proposalView
	Advice    []adviceView
}

func prettyRule(r proposals.ProposedRule) string {
	raw, _ := json.MarshalIndent(r, "", "  ")
	return string(raw)
}

// proposalsPage is the tab "Rules → Proposals": docs/*/protocol/proposals.md's
// third channel, shown to the owner — a draft rule with the numbers
// behind it, and the advice about rules already at work. Nothing here
// does anything until a button is pressed.
func (s *Server) proposalsPage(w http.ResponseWriter, r *http.Request, user string) {
	data := proposalsData{
		pageCommon: s.common(r, user, "rules", 0, r.URL.Query().Get("error")),
		CSRF:       s.csrfToken(r),
	}
	data.Tab = "proposals"

	if s.o.Proposals == nil {
		if data.Error == "" {
			data.Error = s.t(r, "error.proposals_off")
		}
		s.render(w, r, "proposals.html", data)
		return
	}

	var set *rules.Set
	if s.o.Rules != nil {
		set = s.o.Rules.Set()
	}
	list, advice, err := s.o.Proposals.List(time.Now(), set)
	if err != nil {
		data.Error = err.Error()
	}
	for _, p := range list {
		data.Proposals = append(data.Proposals, proposalView{Proposal: p, RuleJSON: prettyRule(p.Rule)})
	}

	byHash := map[string]rules.Rule{}
	if set != nil {
		for _, rule := range set.All() {
			byHash[rule.Hash()] = rule
		}
	}
	for _, a := range advice {
		owner := byHash[a.Rule]
		data.Advice = append(data.Advice, adviceView{Advice: a, RuleID: owner.ID, RuleName: owner.Name})
	}

	s.render(w, r, "proposals.html", data)
}

// decideProposal is what the tab's two buttons post to: do=accept accepts
// a proposal, do=reject rejects a proposal or a piece of advice, both
// with a plain "id" and reject with an optional "reason".
//
// Accept asks for no password: it only writes the rule into rules.json in
// shadow, which decides and blocks nothing until the owner moves it to
// active himself, on the rules page, with the password that step already
// asks for — a second password here would guard a door that opens
// nothing.
func (s *Server) decideProposal(w http.ResponseWriter, r *http.Request, who string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, s.t(r, "error.invalid_form"), http.StatusBadRequest)
		return
	}
	if !s.checkCSRF(r) {
		http.Error(w, s.t(r, "error.foreign_form"), http.StatusForbidden)
		return
	}
	back := "/rules/proposals"
	fail := func(m string) { http.Redirect(w, r, withError(back, m), http.StatusSeeOther) }
	if s.o.Proposals == nil {
		fail(s.t(r, "error.proposals_off"))
		return
	}

	id := r.PostFormValue("id")
	do := r.PostFormValue("do")
	now := time.Now()

	var err error
	switch do {
	case "accept":
		if s.o.Rules == nil {
			fail(s.t(r, "error.rules_off"))
			return
		}
		err = s.o.Proposals.Accept(id, s.o.Rules, who, now)
	case "reject":
		reason := r.PostFormValue("reason")
		if n := utf8.RuneCountInString(reason); n > maxReasonRunes {
			fail(s.t(r, "proposals.reason_too_long", n, maxReasonRunes))
			return
		}
		err = s.o.Proposals.Reject(id, reason, who, now)
	default:
		fail(s.t(r, "error.invalid_form"))
		return
	}
	if err != nil {
		s.o.Log.Error("a cloud proposal was not decided", "id", id, "do", do, "who", who, "err", err)
		fail(s.proposalError(r, err))
		return
	}
	if do == "accept" {
		s.reload(r.Context(), control.ReloadRules)
	}

	s.o.Log.Info("a cloud proposal was decided from the admin UI",
		"id", id, "do", do, "who", who, "address", clientAddr(r))
	http.Redirect(w, r, back, http.StatusSeeOther)
}

// proposalError turns one of proposals.Store's own errors into a message
// in the owner's language; anything else — a disk gone bad — stays as
// the code wrote it, the way every other page's fallback does.
func (s *Server) proposalError(r *http.Request, err error) string {
	var already *proposals.AlreadyDecidedError
	var gone *proposals.NoProposalError
	var isAdvice *proposals.AdviceCannotBeAcceptedError
	var exists *rules.RuleExistsError
	switch {
	case errors.As(err, &already):
		return s.t(r, "proposals.already_decided")
	case errors.As(err, &gone):
		return s.t(r, "proposals.gone", strconv.Quote(gone.ID))
	case errors.As(err, &isAdvice):
		return s.t(r, "proposals.not_a_proposal")
	case errors.As(err, &exists):
		return s.t(r, "proposals.rule_exists", strconv.Quote(exists.ID))
	default:
		return err.Error()
	}
}
