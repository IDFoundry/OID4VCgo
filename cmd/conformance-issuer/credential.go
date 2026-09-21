package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/fxamacker/cbor/v2"

	fapires "github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// issuedCredentialLifetime bounds an issued credential's own "exp"
// claim — HAIP/SD-JWT VC §11.2.3's own RECOMMENDED (not required) way
// to limit a credential's validity, confirmed live as something the
// OIDF conformance suite's own log flags as a WARNING when absent. See
// sdjwtvc.RoundedExp's own doc comment for why the actual exp value is
// day-rounded, not this value added to the raw issuance instant.
const issuedCredentialLifetime = 365 * 24 * time.Hour

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
func credentialHandler(iss *issuer.Issuer, resourceVerifier *fapires.Verifier, credentialURL *url.URL, cfg Config) (http.HandlerFunc, error) {
	additional := sdjwtAdditionalClaims(cfg.Claims)
	mdocNameSpaceElements, mdocDocType, err := mdocNameSpaceElementsFor(cfg.Mdoc)
	if err != nil {
		return nil, fmt.Errorf("mdoc claims: %w", err)
	}

	deps := credentialHandlerDeps{
		iss: iss, resourceVerifier: resourceVerifier, credentialURL: credentialURL, cfg: cfg,
		additional: additional, mdocNameSpaceElements: mdocNameSpaceElements, mdocDocType: mdocDocType,
	}
	return func(w http.ResponseWriter, r *http.Request) {
		serveCredentialRequest(w, r, deps)
	}, nil
}

// credentialHandlerDeps bundles serveCredentialRequest's own fixed,
// per-handler-construction inputs (everything credentialHandler
// precomputes or receives as a parameter) into one value, both to keep
// serveCredentialRequest's own parameter count reasonable and because
// none of these vary per request — only w/r do.
type credentialHandlerDeps struct {
	iss              *issuer.Issuer
	resourceVerifier *fapires.Verifier
	credentialURL    *url.URL
	cfg              Config

	additional            map[string]any
	mdocNameSpaceElements map[string]map[string]interface{}
	mdocDocType           string
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

// mdocFullDateTag is credential/mdoc's own documented convention for a
// full-date element (its own doc comment: "cbor.Tag for one of mdoc's
// date tags (0 for tdate, 1004 for full-date)") — this package has no
// opinion on namespace-specific data models, so the ISO/IEC 18013-5
// org.iso.18013.5.1 namespace's own encoding choice (Table 20: "full-
// date" for birth_date, "tdate or full-date" for issue_date/
// expiry_date — full-date used for all three here, for one consistent
// encoding) is this binary's own call to make, not the library's.
const mdocFullDateTag = 1004

// mdocDateElements names the Table 20 org.iso.18013.5.1 data elements
// whose JSON-config value needs wrapping in an mdocFullDateTag before
// use — see conformanceconfig.MdocConfig.Claims's own doc comment for
// why the raw JSON round-trip alone can't carry this. portrait needs
// its own reinterpretation too (base64 decode into raw bytes), handled
// inline below by name rather than via a second map — every other
// element in cfg.Claims is a plain tstr, needing no transform.
var mdocDateElements = map[string]bool{"birth_date": true, "issue_date": true, "expiry_date": true}

// mdocNameSpaceElementsFor builds credentialHandler's own precomputed
// mso_mdoc namespace/data-element map from cfg (nil when cfg is unset,
// in which case serveCredentialRequest's own mdocClaimsForRequest call
// always returns a nil *mdoc.Claims too) — extracted out of
// credentialHandler itself purely to keep that function's own
// cognitive complexity low.
func mdocNameSpaceElementsFor(cfg *conformanceconfig.MdocConfig) (nameSpaces map[string]map[string]interface{}, docType string, err error) {
	if cfg == nil {
		return nil, "", nil
	}
	elements := make(map[string]interface{}, len(cfg.Claims))
	for name, value := range cfg.Claims {
		switch {
		case mdocDateElements[name]:
			s, ok := value.(string)
			if !ok {
				return nil, "", fmt.Errorf("mdoc claim %q: want a date string, got %T", name, value)
			}
			elements[name] = cbor.Tag{Number: mdocFullDateTag, Content: s}
		case name == "portrait":
			s, ok := value.(string)
			if !ok {
				return nil, "", fmt.Errorf("mdoc claim %q: want a base64 string, got %T", name, value)
			}
			decoded, decErr := base64.StdEncoding.DecodeString(s)
			if decErr != nil {
				return nil, "", fmt.Errorf("mdoc claim %q: decode base64: %w", name, decErr)
			}
			elements[name] = decoded
		default:
			elements[name] = value
		}
	}
	return map[string]map[string]interface{}{cfg.Namespace: elements}, cfg.DocType, nil
}

// serveCredentialRequest is credentialHandler's own returned
// http.HandlerFunc body, factored into a plain named function (rather
// than staying inline as a closure) so its own cognitive complexity is
// judged on its own terms — a closure literal costs extra nesting
// credit for everything inside it, on top of what the same code would
// cost as a standalone function.
func serveCredentialRequest(w http.ResponseWriter, r *http.Request, deps credentialHandlerDeps) {
	// URL is this binary's own configured Credential Endpoint URL, not
	// r.URL — a net/http server request's own URL has no Scheme/Host
	// populated (only Path/RawQuery come off the request line), which
	// would make DPoP's own "htu" comparison fail; mirrors FAPIgo's own
	// cmd/conformance-as/resource.go, which passes its pre-built
	// userinfoURL/accountsURL the same way, never r.URL directly.
	authCtx, err := deps.resourceVerifier.Verify(r.Context(), fapires.VerifyRequest{
		Method: r.Method, URL: deps.credentialURL, Authorization: r.Header.Get("Authorization"),
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
	plaintext, wasEncrypted, err := deps.iss.DecryptRequestBody(body, r.Header.Get("Content-Type"))
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
	var wire wireCredentialRequest
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		http.Error(w, "malformed credential request", http.StatusBadRequest)
		return
	}
	responseEncryption := responseEncryptionFromWire(wire.CredentialResponseEncryption)

	exp := sdjwtvc.RoundedExp(time.Now(), issuedCredentialLifetime)
	auth := issuer.AuthorizedRequest{ClientID: authCtx.ClientID, Scopes: authCtx.Scopes}

	// Both SDJWTClaims and MdocClaims are always supplied (the
	// latter nil when cfg.Mdoc is unset) — issueOne's own
	// cc.Format dispatch picks whichever one actually matches the
	// requested CredentialConfiguration and ignores the other, so
	// this handler doesn't need to itself look up which format
	// wire.CredentialConfigurationID/CredentialIdentifier resolves
	// to.
	mdocClaims := mdocClaimsForRequest(deps.mdocDocType, deps.mdocNameSpaceElements, issuedCredentialLifetime)

	result, err := deps.iss.RequestCredential(r.Context(), auth, issuer.CredentialRequest{
		CredentialConfigurationID: wire.CredentialConfigurationID,
		CredentialIdentifier:      wire.CredentialIdentifier,
		Proofs:                    wire.Proofs,
		SDJWTClaims:               &sdjwtvc.Claims{VCT: deps.cfg.VCT, Exp: &exp, Additional: deps.additional},
		MdocClaims:                mdocClaims,
		RequestWasEncrypted:       wasEncrypted,
		ResponseEncryption:        responseEncryption,
	})
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	encoded, contentType, err := deps.iss.EncryptResponseBody(resultJSON, responseEncryption)
	if err != nil {
		issuer.WriteError(w, err)
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(encoded)
}
