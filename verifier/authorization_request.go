package verifier

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// checkQueryFormats refuses a query asking for a credential format this
// package doesn't verify, or one Config.VPFormatsSupported doesn't
// advertise: every answer to it would be refused, or the Wallet would
// refuse the request.
func (v *Verifier) checkQueryFormats(query dcql.Query) error {
	for _, cq := range query.Credentials {
		if cq.Format != sdjwtvc.CredentialFormat && cq.Format != mdoc.CredentialFormat {
			return fmt.Errorf("credential query %q asks for format %q, which this Verifier can't verify (%q or %q)", cq.ID, cq.Format, sdjwtvc.CredentialFormat, mdoc.CredentialFormat)
		}
		if _, ok := v.cfg.VPFormatsSupported[cq.Format]; !ok {
			return fmt.Errorf("credential query %q asks for format %q, which config.vp_formats_supported doesn't list", cq.ID, cq.Format)
		}
	}
	return nil
}

// requestObjectTyp is the Request Object JWS's own "typ" header value
// (§5, RFC9101) — Wallets MUST reject a Request Object where it's
// missing or has any other value.
const requestObjectTyp = "oauth-authz-req+jwt"

// selfIssuedAudience is the Request Object's own "aud" claim value
// under Static Discovery metadata (§5.8) — the case this package's
// x509_hash-identified Verifier always falls under, since it performs
// no Dynamic Discovery of its own metadata. A SIOPv2-inherited
// symbolic value, legal standalone per §5.8's own note.
const selfIssuedAudience = "https://self-issued.me/v2"

// nonceEntropyBytes matches issuer's own nonce-generation convention
// (256-bit) for both the Authorization Request's own "nonce" and the
// response-encryption JWK's own "kid".
const nonceEntropyBytes = 32

// BuildAuthorizationRequestRequest is the input to
// BuildAuthorizationRequest.
type BuildAuthorizationRequestRequest struct {
	// Query is REQUIRED: the DCQL query (§6) describing the
	// Credential(s)/claims being requested.
	Query dcql.Query

	// State is round-tripped back by the Wallet's own response. It is
	// REQUIRED when any of Query's credentials doesn't require
	// cryptographic holder binding (OID4VP 1.0 §5.3), and otherwise
	// OPTIONAL; it may hold only ASCII letters, digits, "-", ".", "_"
	// and "~".
	State string

	// WalletNonce is OPTIONAL: the "wallet_nonce" value a Wallet sent
	// when fetching this Request Object over POST (§5.10, Request URI
	// Method post). When set, it's embedded as this Request Object's
	// own "wallet_nonce" claim — §5.10.1 requires the Verifier "MUST
	// use it as the wallet_nonce value in the signed authorization
	// request object", so the Wallet can confirm the object it
	// received is fresh, not replayed. Leave empty for a plain GET
	// fetch, or a POST that didn't include one.
	WalletNonce string
}

// BuildAuthorizationRequestResult is returned by a successful
// BuildAuthorizationRequest.
type BuildAuthorizationRequestResult struct {
	// RequestObject is the signed JWS (JAR Request Object, RFC9101) —
	// what a caller hosts at a request_uri (or otherwise delivers to
	// a Wallet) to actually initiate the flow. This package doesn't
	// host it itself — see the package doc comment.
	RequestObject string

	// ClientID is this Verifier's own "x509_hash:..." Client
	// Identifier, for the caller's own "openid4vp://" deep-link
	// construction (client_id + request_uri).
	ClientID string

	// Nonce is the fresh nonce baked into the Request Object
	// (§5.2/§14.1.2) — the caller must retain it to validate the
	// eventual response's own Holder Binding proof. This package has
	// no nonce-replay protection of its own: retaining Nonce only for
	// lookup (passing it as VerifyResponseRequest.ExpectedNonce) is
	// NOT enough on its own — the caller must also mark it consumed
	// once VerifyResponse succeeds (or once this request is abandoned)
	// so it can never be presented again. Skipping that silently
	// permits a captured, previously-successful direct_post.jwt
	// response to be replayed.
	Nonce string

	// ResponseDecryptionKey is the ephemeral P-256 private key
	// generated for this one request's own response encryption — the
	// caller must retain it to decrypt the eventual direct_post.jwt
	// response via ParseDirectPostJWTResponse.
	ResponseDecryptionKey *ecdsa.PrivateKey

	// ResponseEncryptionKeyID is the "kid" of ResponseDecryptionKey's
	// public half in the Request Object's client_metadata.jwks. The
	// Wallet's encrypted response names it in its JWE header, before
	// anything inside can be read — so a Verifier with several requests
	// open routes each response to its request (and decryption key) by
	// ResponseKeyID(response) == ResponseEncryptionKeyID.
	ResponseEncryptionKeyID string
}

// BuildAuthorizationRequest builds a signed, HAIP-§5-profiled
// redirect-flow Authorization Request: "response_type":"vp_token",
// "response_mode":"direct_post.jwt" (HAIP §5.1's own mandatory
// encryption for the redirect flow), the "x509_hash" Client Identifier
// Prefix (HAIP §5's own mandated prefix for a signed request, the only
// one this package supports), a fresh "nonce", req.Query as
// "dcql_query", and a "client_metadata" advertising a fresh ephemeral
// P-256 ECDH-ES response-encryption key plus
// Config.EncValuesSupported.
//
// It doesn't host the built Request Object at a request_uri, parse a
// response, or do anything past building and signing — see the package
// doc comment for what's still missing.
func (v *Verifier) BuildAuthorizationRequest(req BuildAuthorizationRequestRequest) (BuildAuthorizationRequestResult, error) {
	if err := req.Query.Validate(); err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: dcql_query: %w", err)
	}
	if err := v.checkQueryFormats(req.Query); err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: dcql_query: %w", err)
	}
	if err := checkRequestState(req.State, req.Query); err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: %w", err)
	}

	nonce, err := randomToken(v.deps.Random)
	if err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: generate nonce: %w", err)
	}
	encKey, err := v.newResponseEncryptionKey()
	if err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: %w", err)
	}
	requestObject, kid, err := v.signAuthorizationRequest(authorizationRequest{
		query: req.Query, state: req.State, nonce: nonce, encKey: encKey, walletNonce: req.WalletNonce,
	})
	if err != nil {
		return BuildAuthorizationRequestResult{}, fmt.Errorf("verifier: build authorization request: %w", err)
	}
	return BuildAuthorizationRequestResult{
		RequestObject: requestObject, ClientID: v.clientID, Nonce: nonce,
		ResponseDecryptionKey: encKey, ResponseEncryptionKeyID: kid,
	}, nil
}

// authorizationRequest is what signAuthorizationRequest signs: a
// redirect-flow request's query, state, nonce and response encryption
// key, which a request keeps once built, and what may differ from one
// fetch of it to the next: the wallet_nonce of a request_uri POST
// (OpenID4VP 1.0 §5.10) and the client_metadata narrowed to that
// POST's wallet_metadata (walletFit).
type authorizationRequest struct {
	query       dcql.Query
	state       string
	nonce       string
	encKey      *ecdsa.PrivateKey
	walletNonce string
	fit         *walletFit
}

// signAuthorizationRequest signs req's Request Object and returns it
// with its response encryption key's kid. req's query and state must
// already have been checked, as BuildAuthorizationRequest checks them.
func (v *Verifier) signAuthorizationRequest(req authorizationRequest) (requestObject, kid string, err error) {
	clientMetadata, kid, err := v.responseEncryptionMetadata(req.encKey, req.fit)
	if err != nil {
		return "", "", err
	}
	payload := map[string]any{
		"iss":             v.clientID,
		"aud":             selfIssuedAudience,
		"response_type":   "vp_token",
		"response_mode":   "direct_post.jwt",
		"client_id":       v.clientID,
		"response_uri":    v.cfg.ResponseURI.String(),
		"nonce":           req.nonce,
		"dcql_query":      req.query,
		"client_metadata": clientMetadata,
	}
	if req.state != "" {
		payload["state"] = req.state
	}
	if req.walletNonce != "" {
		payload["wallet_nonce"] = req.walletNonce
	}
	if info, err := v.verifierInfoFor(req.query); err != nil {
		return "", "", err
	} else if info != nil {
		payload["verifier_info"] = info
	}
	requestObject, err = v.signRequestObject(payload)
	if err != nil {
		return "", "", err
	}
	return requestObject, kid, nil
}

// buildResponseEncryptionMetadata generates a fresh ephemeral P-256
// key for this one request's own response encryption and returns its
// own "client_metadata" value (§5.1's own jwks/
// encrypted_response_enc_values_supported shape) alongside the key and
// its "kid" — what BuildDCAPIAuthorizationRequest needs, as
// BuildAuthorizationRequest does, since both flows decrypt whichever
// of direct_post.jwt/dc_api.jwt the Wallet responds with the same way.
func (v *Verifier) buildResponseEncryptionMetadata() (map[string]any, *ecdsa.PrivateKey, string, error) {
	encKey, err := v.newResponseEncryptionKey()
	if err != nil {
		return nil, nil, "", err
	}
	clientMetadata, kid, err := v.responseEncryptionMetadata(encKey, nil)
	if err != nil {
		return nil, nil, "", err
	}
	return clientMetadata, encKey, kid, nil
}

// newResponseEncryptionKey generates a request's ephemeral P-256
// response encryption key (HAIP 1.0 §5).
func (v *Verifier) newResponseEncryptionKey() (*ecdsa.PrivateKey, error) {
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), v.deps.Random)
	if err != nil {
		return nil, fmt.Errorf("generate response encryption key: %w", err)
	}
	return encKey, nil
}

// responseEncryptionMetadata is the "client_metadata" of a request
// whose response is encrypted to encKey, with encKey's kid: this
// Verifier's own encrypted_response_enc_values_supported and
// vp_formats_supported, or, with fit, those narrowed to what a
// Wallet's wallet_metadata says it supports (OpenID4VP 1.0 §5.10).
func (v *Verifier) responseEncryptionMetadata(encKey *ecdsa.PrivateKey, fit *walletFit) (map[string]any, string, error) {
	encJWK, err := jwk.Marshal(&encKey.PublicKey)
	if err != nil {
		return nil, "", fmt.Errorf("marshal response encryption key: %w", err)
	}
	kid, err := encJWK.Thumbprint()
	if err != nil {
		return nil, "", fmt.Errorf("thumbprint response encryption key: %w", err)
	}
	encValues, vpFormats := any(v.cfg.EncValuesSupported), any(v.cfg.VPFormatsSupported)
	if fit != nil {
		encValues, vpFormats = fit.encValues, fit.vpFormats
	}
	clientMetadata := map[string]any{
		"jwks": jwk.Set{Keys: []jwk.SetEntry{{JWK: encJWK, Kid: kid, Use: "enc", Alg: string(jwe.ECDHES)}}},
		"encrypted_response_enc_values_supported": encValues,
		"vp_formats_supported":                    vpFormats,
	}
	return clientMetadata, kid, nil
}

// signRequestObject marshals payload and signs it as a JAR Request
// Object (RFC9101): the "typ"/"x5c" header this package's own
// x509_hash Client Identifier Prefix always uses, regardless of which
// flow's own payload shape is being signed.
func (v *Verifier) signRequestObject(payload map[string]any) (string, error) {
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	header := map[string]any{
		"typ": requestObjectTyp,
		"x5c": v.requestX5C(),
	}
	requestObject, err := jose.Sign(v.cfg.SigningAlg, v.deps.Signer, header, payloadJSON)
	if err != nil {
		return "", fmt.Errorf("sign request object: %w", err)
	}
	return requestObject, nil
}

// randomToken generates a fresh, unpredictable, base64url-encoded
// (RawURLEncoding, matching this repo's own nonce/notification_id
// convention) 256-bit value from random.
func randomToken(random io.Reader) (string, error) {
	raw := make([]byte, nonceEntropyBytes)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// requestX5C is the Request Object's x5c: the client certificate, then
// its chain to (not including) the trust anchor.
func (v *Verifier) requestX5C() []string {
	x5c := []string{base64.StdEncoding.EncodeToString(v.cfg.ClientCertificate.Raw)}
	for _, c := range v.cfg.ClientCertificateChain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c.Raw))
	}
	return x5c
}

// checkRequestState checks a request's state: present when a credential
// of query doesn't require cryptographic holder binding, as only state
// then ties the response to this request (OID4VP 1.0 §5.3), and made of
// URL-safe ASCII only (letters, digits, "-", ".", "_", "~").
func checkRequestState(state string, query dcql.Query) error {
	for _, c := range query.Credentials {
		if !c.RequiresCryptographicHolderBinding() && state == "" {
			return fmt.Errorf("state is required: credential %q doesn't require cryptographic holder binding (OID4VP 1.0 §5.3)", c.ID)
		}
	}
	for i := 0; i < len(state); i++ {
		if !isStateByte(state[i]) {
			return fmt.Errorf("state may hold only ASCII letters, digits, '-', '.', '_' and '~'")
		}
	}
	return nil
}

// isStateByte reports whether b may appear in a state: an ASCII letter
// or digit, '-', '.', '_' or '~'.
func isStateByte(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	return b == '-' || b == '.' || b == '_' || b == '~'
}
