package main

import (
	"encoding/json"
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// authorizationServerMetadataHandler serves GET
// /.well-known/openid-configuration — this binary's own FAPI 2.0
// Authorization Server metadata, distinct from the OID4VCI Credential
// Issuer metadata credentialIssuerMetadataHandler serves at
// /.well-known/openid-credential-issuer (§12.2). server.Metadata
// already carries everything, dpop_signing_alg_values_supported
// included (RFC 9449 §5.1); this binary's own Config.OAuthOnly means
// no OIDC fields to add.
func authorizationServerMetadataHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(srv.Metadata(r.Context()))
	}
}
