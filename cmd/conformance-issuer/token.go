package main

import (
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// tokenHandler serves POST /token — authorization_code and
// refresh_token, and the pre-authorized code grant when preAuthorized
// is non-nil (Config.Offers). No client_credentials (this binary's one
// test client has no end-user-less use case here) and no CIBA (not part
// of this HAIP test plan's own module list).
func tokenHandler(srv *server.Server, preAuthorized func(http.ResponseWriter, *http.Request, server.TokenEndpointRequest)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		req, err := server.TokenEndpointRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}

		var result server.TokenResult
		switch grantType := req.GrantType(); {
		case grantType == "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), req.AuthorizationCodeExchange())
		case grantType == "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), req.RefreshToken())
		case grantType == preAuthorizedCodeGrantType && preAuthorized != nil:
			preAuthorized(w, r, req)
			return
		default:
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorUnsupportedGrantType, "unsupported grant_type")
			return
		}
		if err != nil {
			writeOAuthJSONError(w, err)
			return
		}
		result.WriteJSON(w)
	}
}
