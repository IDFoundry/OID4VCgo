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
		form, err := server.FormRequestFromHTTP(r)
		if err != nil {
			writeRawOAuthError(w, http.StatusBadRequest, server.ErrorInvalidRequest, err.Error())
			return
		}
		dpopProofs := r.Header.Values("DPoP")
		peerCert := server.PeerCertificateFromHTTP(r)

		var result server.TokenResult
		switch form.Get("grant_type") {
		case "authorization_code":
			result, err = srv.ExchangeAuthorizationCode(r.Context(), server.AuthorizationCodeExchangeRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
		case "refresh_token":
			result, err = srv.RefreshAccessToken(r.Context(), server.RefreshTokenRequest{HTTP: form, DPoPProofs: dpopProofs, PeerCertificate: peerCert})
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
