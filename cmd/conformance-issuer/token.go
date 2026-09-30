package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// tokenHandler serves POST /token — authorization_code and
// refresh_token only. No client_credentials (this binary's one test
// client has no end-user-less use case here) and no CIBA (not part of
// this HAIP test plan's own module list).
func tokenHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := server.TokenEndpointRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}

		var result server.TokenResult
		switch req.GrantType() {
		case "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
		case "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), req.RefreshToken())
		default:
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorUnsupportedGrantType, "grant_type must be authorization_code or refresh_token")
			return
		}
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}
