package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	fapires "github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/issuer"
)

// credentialIssuerMetadataHandler serves GET
// /.well-known/openid-credential-issuer (§12.2) — issuer.Metadata is
// already the wire-marshalable document (see issuer/metadata.go's own
// json tags), so this is a direct encode, no adapter struct needed —
// unlike authorizationServerMetadataHandler's own server.Metadata.
func credentialIssuerMetadataHandler(iss *issuer.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(iss.Metadata())
	}
}

// nonceHandler serves the OID4VCI Nonce Endpoint (§7) — not a
// protected resource (issuer.RequestNonce's own doc comment), so no
// resource.Verifier check here.
func nonceHandler(iss *issuer.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		result, err := iss.RequestNonce(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result.WriteJSON(w)
	}
}

// wireCredentialRequest is the Credential Request's own wire shape
// (§8.2) — this binary's own job to parse, matching this repo's
// established "issuer doesn't own the HTTP handler" boundary (see
// issuer/credential_endpoint.go's own doc comment).
type wireCredentialRequest struct {
	CredentialConfigurationID string              `json:"credential_configuration_id"`
	CredentialIdentifier      string              `json:"credential_identifier"`
	Proofs                    map[string][]string `json:"proofs"`
}

// credentialHandler serves the Credential Endpoint (§8): verifies the
// presented access token via resourceVerifier (fapigo/resource,
// per issuer/resource_verifier.go's own recipe), adapts the result
// into issuer.AuthorizedRequest, parses the wire request body, and
// calls RequestCredential with vct/claims fixed to whatever cfg
// configures — issuer.Issuer has no user database of its own
// (CredentialRequest.SDJWTClaims' own doc comment), so this binary's
// own static test data stands in for one. No request/response
// encryption support yet and no credential_identifier-based requests
// — see README's own "Status".
func credentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config) http.HandlerFunc {
	additional := make(map[string]any, len(cfg.Claims))
	for name, value := range cfg.Claims {
		additional[name] = sdjwtvc.SD(value)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// URL is this binary's own configured Credential Endpoint URL,
		// not r.URL — a net/http server request's own URL has no
		// Scheme/Host populated (only Path/RawQuery come off the
		// request line), which would make DPoP's own "htu" comparison
		// fail; mirrors FAPIgo's own cmd/conformance-as/resource.go,
		// which passes its pre-built userinfoURL/accountsURL the same
		// way, never r.URL directly.
		authCtx, err := resourceVerifier.Verify(r.Context(), fapires.VerifyRequest{
			Method: r.Method, URL: credentialURL, Authorization: r.Header.Get("Authorization"),
			DPoPProofs: r.Header.Values("DPoP"), PeerCertificate: fapires.PeerCertificateFromHTTP(r),
		})
		if err != nil {
			fapires.WriteError(w, err)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			return
		}
		var wire wireCredentialRequest
		if err := json.Unmarshal(body, &wire); err != nil {
			http.Error(w, "malformed credential request", http.StatusBadRequest)
			return
		}

		auth := issuer.AuthorizedRequest{ClientID: authCtx.ClientID, Scopes: authCtx.Scopes}
		result, err := iss.RequestCredential(r.Context(), auth, issuer.CredentialRequest{
			CredentialConfigurationID: wire.CredentialConfigurationID,
			CredentialIdentifier:      wire.CredentialIdentifier,
			Proofs:                    wire.Proofs,
			SDJWTClaims:               &sdjwtvc.Claims{VCT: cfg.VCT, Additional: additional},
		})
		if err != nil {
			writeIssuerError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}
}

// writeIssuerError writes err as a Credential Endpoint error response
// (*issuer.Error's own WriteJSON) when it is one, or a generic 500
// otherwise — matches fapires.WriteError's own fallback shape, since
// issuer has no equivalent top-level helper of its own.
func writeIssuerError(w http.ResponseWriter, err error) {
	var issErr *issuer.Error
	if errors.As(err, &issErr) {
		issErr.WriteJSON(w)
		return
	}
	http.Error(w, "server_error", http.StatusInternalServerError)
}
