package admin

import "net/http"

// TODO(T10): the tab of docs/*/protocol/proposals.md's third channel —
// proposals and advice from the cloud, and the owner's decisions about
// them. Not implemented yet.

func (s *Server) proposalsPage(w http.ResponseWriter, r *http.Request, user string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) decideProposal(w http.ResponseWriter, r *http.Request, who string) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
