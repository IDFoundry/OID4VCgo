package main

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	fapires "github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/issuer"
)

// issuedCredentialLifetime bounds an issued credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent. See
// conformancecert.CredentialExp's own doc comment for why the actual
// exp value is day-rounded, not this value added to the raw issuance
// instant.
const issuedCredentialLifetime = 365 * 24 * time.Hour

// openidVCIIssuerMetadataTyp is the signed Credential Issuer Metadata
// JWT's own mandatory "typ" header value (§12.2.3).
const openidVCIIssuerMetadataTyp = "openidvci-issuer-metadata+jwt"

// signCredentialIssuerMetadata signs meta as a compact JWS per §12.2.3:
// "All metadata parameters used by the Credential Issuer MUST be added
// as top-level claims in the JWS payload" — json.Marshal already
// produces exactly that shape (issuer.Metadata's own json tags are
// what §12.2.4 defines), so this just adds the REQUIRED "sub" (the
// Credential Issuer Identifier — read back out of the marshaled
// metadata itself, since it's the same value as its own
// "credential_issuer" member) and "iat" claims. "iss"/"exp" are both
// OPTIONAL and left out: nothing about this binary's own identity is
// distinguishable from credential_issuer, and metadata has no
// separate validity window of its own. The "x5c" header entry is how
// a Wallet resolves the signing key here (§12.2.3: "e.g., using JOSE
// header parameters like x5c, kid or trust_chain") — this repo's own
// established convention (see
// verifier/authorization_request.go's signRequestObject).
func signCredentialIssuerMetadata(meta issuer.Metadata, signer crypto.Signer, cert *x509.Certificate) (string, error) {
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		return "", fmt.Errorf("marshal metadata: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(metaJSON, &claims); err != nil {
		return "", fmt.Errorf("unmarshal metadata into claims: %w", err)
	}
	sub, _ := claims["credential_issuer"].(string)
	if sub == "" {
		return "", fmt.Errorf("metadata: credential_issuer is empty, cannot set sub claim")
	}
	claims["sub"] = sub
	claims["iat"] = time.Now().Unix()

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal signed metadata claims: %w", err)
	}
	header := map[string]any{
		"typ": openidVCIIssuerMetadataTyp,
		"x5c": []string{base64.StdEncoding.EncodeToString(cert.Raw)},
	}
	return jose.Sign(jose.ES256, signer, header, claimsJSON)
}

// credentialIssuerMetadataHandler serves GET
// /.well-known/openid-credential-issuer (§12.2). §12.2.2 makes this
// pure content negotiation, not a separate endpoint or field: a
// Wallet's Accept header names application/json and/or application/jwt,
// this binary MUST always support the former and MAY support the
// latter (confirmed live: §12.2.2's own "the Credential Issuer MUST
// indicate the media type of the returned Metadata using the HTTP
// Content-Type header" — the OIDF suite's metadata-test-signed module
// detects support by that header, not by any request-side signal this
// binary reads). Signing failure falls back to plain JSON rather than
// a 500 — an operator error in signer/cert config shouldn't take down
// the one endpoint every OID4VCI flow starts with.
func credentialIssuerMetadataHandler(iss *issuer.Issuer, signer crypto.Signer, cert *x509.Certificate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		meta := iss.Metadata()
		if strings.Contains(r.Header.Get("Accept"), "application/jwt") {
			if signed, err := signCredentialIssuerMetadata(meta, signer, cert); err == nil {
				w.Header().Set("Content-Type", "application/jwt")
				_, _ = w.Write([]byte(signed))
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(meta)
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
	CredentialConfigurationID    string                  `json:"credential_configuration_id"`
	CredentialIdentifier         string                  `json:"credential_identifier"`
	Proofs                       map[string][]string     `json:"proofs"`
	CredentialResponseEncryption *wireResponseEncryption `json:"credential_response_encryption"`
}

// wireResponseEncryption is the Credential Request's own optional
// "credential_response_encryption" object (§8.2) — this binary's own
// job to parse into an *issuer.ResponseEncryptionRequest, since that
// type carries no JSON tags of its own (issuer/encryption.go's own
// doc comment: it's populated by the caller, not unmarshaled
// directly).
type wireResponseEncryption struct {
	JWK json.RawMessage `json:"jwk"`
	Enc string          `json:"enc"`
	Zip string          `json:"zip"`
}

// responseEncryptionFromWire adapts wire (nil when the Credential
// Request carried no "credential_response_encryption" object) into the
// *issuer.ResponseEncryptionRequest RequestCredential expects.
func responseEncryptionFromWire(wire *wireResponseEncryption) *issuer.ResponseEncryptionRequest {
	if wire == nil {
		return nil
	}
	return &issuer.ResponseEncryptionRequest{
		JWK: wire.JWK, Enc: jwe.Enc(wire.Enc), Zip: jwe.Zip(wire.Zip),
	}
}

// mdocClaimsForRequest builds this request's own *mdoc.Claims from
// nameSpaces (cfg.Mdoc.Claims, precomputed once by credentialHandler —
// nil when cfg.Mdoc is unset, in which case this returns nil too) and
// docType, with a fresh Signed/ValidFrom/ValidUntil validity window
// spanning lifetime from now.
func mdocClaimsForRequest(docType string, nameSpaces map[string]map[string]interface{}, lifetime time.Duration) *mdoc.Claims {
	if nameSpaces == nil {
		return nil
	}
	now := time.Now()
	return &mdoc.Claims{
		DocType: docType, NameSpaces: nameSpaces,
		Signed: now, ValidFrom: now, ValidUntil: now.Add(lifetime),
	}
}

// credentialHandler serves the Credential Endpoint (§8): verifies the
// presented access token via resourceVerifier (fapigo/resource,
// per issuer/resource_verifier.go's own recipe), adapts the result
// into issuer.AuthorizedRequest, decrypts the request body if it
// arrived as a JWE (§10, via iss.DecryptRequestBody), parses the wire
// request body, and calls RequestCredential with vct/claims fixed to
// whatever cfg configures — issuer.Issuer has no user database of its
// own (CredentialRequest.SDJWTClaims' own doc comment), so this
// binary's own static test data stands in for one. The response is
// encrypted back (§10, via iss.EncryptResponseBody) whenever the
// request's own "credential_response_encryption" asked for it — both
// directions delegate entirely to issuer/encryption.go's own already-
// tested logic, this handler only translates wire JSON to/from it. No
// credential_identifier-based requests yet — see README's own
// "Status".
func credentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config) http.HandlerFunc {
	additional := sdjwtAdditionalClaims(cfg.Claims)
	mdocNameSpaceElements, mdocDocType := mdocNameSpaceElementsFor(cfg.Mdoc)

	return func(w http.ResponseWriter, r *http.Request) {
		serveCredentialRequest(w, r, iss, resourceVerifier, credentialURL, cfg, additional, mdocNameSpaceElements, mdocDocType)
	}
}

// sdjwtAdditionalClaims builds credentialHandler's own precomputed
// SD-JWT "Additional" claim map (every entry selectively disclosable)
// from claims — extracted out of credentialHandler itself purely to
// keep that function's own cognitive complexity low.
func sdjwtAdditionalClaims(claims map[string]string) map[string]any {
	additional := make(map[string]any, len(claims))
	for name, value := range claims {
		additional[name] = sdjwtvc.SD(value)
	}
	return additional
}

// mdocNameSpaceElementsFor builds credentialHandler's own precomputed
// mso_mdoc namespace/data-element map from cfg (nil when cfg is unset,
// in which case serveCredentialRequest's own mdocClaimsForRequest call
// always returns a nil *mdoc.Claims too) — extracted out of
// credentialHandler itself purely to keep that function's own
// cognitive complexity low.
func mdocNameSpaceElementsFor(cfg *MdocConfig) (nameSpaces map[string]map[string]interface{}, docType string) {
	if cfg == nil {
		return nil, ""
	}
	elements := make(map[string]interface{}, len(cfg.Claims))
	for name, value := range cfg.Claims {
		elements[name] = value
	}
	return map[string]map[string]interface{}{cfg.Namespace: elements}, cfg.DocType
}

// serveCredentialRequest is credentialHandler's own returned
// http.HandlerFunc body, factored into a plain named function (rather
// than staying inline as a closure) so its own cognitive complexity is
// judged on its own terms — a closure literal costs extra nesting
// credit for everything inside it, on top of what the same code would
// cost as a standalone function.
func serveCredentialRequest(
	w http.ResponseWriter, r *http.Request,
	iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config,
	additional map[string]any, mdocNameSpaceElements map[string]map[string]interface{}, mdocDocType string,
) {
	// URL is this binary's own configured Credential Endpoint URL, not
	// r.URL — a net/http server request's own URL has no Scheme/Host
	// populated (only Path/RawQuery come off the request line), which
	// would make DPoP's own "htu" comparison fail; mirrors FAPIgo's own
	// cmd/conformance-as/resource.go, which passes its pre-built
	// userinfoURL/accountsURL the same way, never r.URL directly.
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
	plaintext, wasEncrypted, err := iss.DecryptRequestBody(body, r.Header.Get("Content-Type"))
	if err != nil {
		writeIssuerError(w, err)
		return
	}
	var wire wireCredentialRequest
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		http.Error(w, "malformed credential request", http.StatusBadRequest)
		return
	}
	responseEncryption := responseEncryptionFromWire(wire.CredentialResponseEncryption)

	exp := conformancecert.CredentialExp(time.Now(), issuedCredentialLifetime)
	auth := issuer.AuthorizedRequest{ClientID: authCtx.ClientID, Scopes: authCtx.Scopes}

	// Both SDJWTClaims and MdocClaims are always supplied (the
	// latter nil when cfg.Mdoc is unset) — issueOne's own
	// cc.Format dispatch picks whichever one actually matches the
	// requested CredentialConfiguration and ignores the other, so
	// this handler doesn't need to itself look up which format
	// wire.CredentialConfigurationID/CredentialIdentifier resolves
	// to.
	mdocClaims := mdocClaimsForRequest(mdocDocType, mdocNameSpaceElements, issuedCredentialLifetime)

	result, err := iss.RequestCredential(r.Context(), auth, issuer.CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		CredentialIdentifier:      wire.CredentialIdentifier,
		Proofs:                    wire.Proofs,
		SDJWTClaims:               &sdjwtvc.Claims{VCT: cfg.VCT, Exp: &exp, Additional: additional},
		MdocClaims:                mdocClaims,
		RequestWasEncrypted:       wasEncrypted,
		ResponseEncryption:        responseEncryption,
	})
	if err != nil {
		writeIssuerError(w, err)
		return
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, contentType, err := iss.EncryptResponseBody(resultJSON, responseEncryption)
	if err != nil {
		writeIssuerError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(encoded)
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
