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
	mux.HandleFunc("GET /.well-known/openid-configuration", authorizationServerMetadataHandler(srv))
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
