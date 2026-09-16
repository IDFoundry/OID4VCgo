package main

import (
	"net/http"
	"net/url"

	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"

	"github.com/idfoundry/oid4vcigo/issuer"
)

// newRouter wires the FAPI 2.0 Authorization Server endpoints
// (fapigo/server) and the OID4VCI Credential Issuer endpoints
// (oid4vcigo/issuer) onto one plain net/http.ServeMux — mirrors
// FAPIgo's own cmd/conformance-as/router.go's "no third-party router"
// stance.
func newRouter(srv *server.Server, iss *issuer.Issuer, resourceVerifier *fapires.Verifier, consent *consentHandler, credentialURL *url.URL, cfg Config) *http.ServeMux {
	mux := http.NewServeMux()
	metadataHandler := authorizationServerMetadataHandler(srv)
	mux.HandleFunc("GET /.well-known/openid-configuration", metadataHandler)
	// cfg.OAuthOnly means this AS implements no OIDC surface at all
	// (see wiring.go), so RFC 8414 §3.1's own plain-OAuth well-known
	// path is the more accurate identity — serve the same document
	// there too rather than only at OIDC Discovery's own path. A
	// wallet that derives this path from the Credential Issuer
	// Metadata's own (OPTIONAL) missing "authorization_servers" entry,
	// per RFC 8414's own fallback derivation, needs this: confirmed
	// live against the OpenID Foundation conformance suite's own
	// oid4vci-1_0-issuer-haip-test-plan metadata-test module, whose
	// plain_oauth-profiled variant fetches exactly this path and 404s
	// without it.
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", metadataHandler)
	mux.HandleFunc("GET /jwks", jwksHandler(srv))
	mux.HandleFunc("POST /par", parHandler(srv))
	mux.HandleFunc("GET /authorize", consent.handleBegin)
	mux.HandleFunc("POST /authorize/decision", consent.handleDecision)
	mux.HandleFunc("POST /token", tokenHandler(srv))

	mux.HandleFunc("GET /.well-known/openid-credential-issuer", credentialIssuerMetadataHandler(iss))
	mux.HandleFunc("POST /nonce", nonceHandler(iss))
	mux.HandleFunc("POST /credential", credentialHandler(iss, resourceVerifier, credentialURL, cfg))
	return mux
}
