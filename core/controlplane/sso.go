package controlplane

// OIDC single sign-on for the control plane.
//
// Implemented in the next commit (platform model item 3): the
// handlers below are placeholders that answer 404 so the
// server builds and runs without SSO. The login page offers
// the SSO button only when SSO is configured AND implemented.

import "net/http"

// handleSSO routes /sso/* requests. Placeholder: SSO lands in
// the following commit.
func (s *Server) handleSSO(w http.ResponseWriter, r *http.Request) {
	http.NotFound(w, r)
}
