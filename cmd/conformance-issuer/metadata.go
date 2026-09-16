package main

import (
	"encoding/json"
	"net/http"

	"github.com/idfoundry/fapigo/server"
)

// wireMetadata extends server.Metadata with dpop_signing_alg_values_supported
// — mirrors FAPIgo's own cmd/conformance-as/metadata.go, trimmed: this
// binary's own Config.OAuthOnly means no scopes_supported/
// claims_supported/userinfo_endpoint to add (no OIDC surface at all).
type wireMetadata struct {
	server.Metadata
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
}

var dpopSigningAlgValuesSupported = server.RecommendedAlgorithmSet().Strings()

// authorizationServerMetadataHandler serves GET
// /.well-known/openid-configuration — this binary's own FAPI 2.0
// Authorization Server metadata, distinct from the OID4VCI Credential
// Issuer metadata credentialIssuerMetadataHandler serves at
// /.well-known/openid-credential-issuer (§12.2).
func authorizationServerMetadataHandler(srv *server.Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		doc := wireMetadata{Metadata: srv.Metadata(r.Context()), DPoPSigningAlgValuesSupported: dpopSigningAlgValuesSupported}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
