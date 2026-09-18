package main

import (
	"crypto"
	"crypto/x509"
	"net/http"
	"net/url"

	fapires "github.com/idfoundry/fapigo/resource"
	"github.com/idfoundry/fapigo/server"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// newRouter wires the FAPI 2.0 Authorization Server endpoints
// (fapigo/server) and the OID4VCI Credential Issuer endpoints
// (oid4vcgo/issuer) onto one plain net/http.ServeMux — mirrors
// FAPIgo's own cmd/conformance-as/router.go's "no third-party router"
// stance. metadataSigner/metadataCert are the same credential-issuer
// signing key/certificate pair issuer.Dependencies.SDJWTSigner already
// uses (see wiring.go) — reused here for signed Credential Issuer
// Metadata (§12.2.3) rather than parsed a second time per request.
func newRouter(srv *server.Server, iss *issuer.Issuer, resourceVerifier *fapires.Verifier, consent *consentHandler, credentialURL *url.URL, cfg Config, metadataSigner crypto.Signer, metadataCert *x509.Certificate) (*http.ServeMux, error) {
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

	mux.HandleFunc("GET /.well-known/openid-credential-issuer", issuer.MetadataHandler(iss, metadataSigner, jose.ES256, metadataCert))
	mux.HandleFunc("POST /nonce", nonceHandler(iss))
	credHandler, err := credentialHandler(iss, resourceVerifier, credentialURL, cfg)
	if err != nil {
		return nil, err
	}
	mux.HandleFunc("POST /credential", credHandler)
	return mux, nil
}
