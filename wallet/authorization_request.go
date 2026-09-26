package wallet

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/idfoundry/fapigo/fapihttp"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// requestObjectTyp is the Request Object JWS's own mandatory "typ"
// header value (OID4VP §5, RFC9101) — a Wallet MUST reject one where
// it's missing or has any other value.
const requestObjectTyp = "oauth-authz-req+jwt"

// ParseAuthorizationRequestParams is the input to
// ParseAuthorizationRequest. Not to be confused with
// BuildAuthorizationRequest (authorization.go), this package's
// unrelated OID4VCI Authorization Code Flow request builder — this
// file is OID4VP (§5), the Wallet-side counterpart to
// verifier.BuildAuthorizationRequest/ParseDirectPostJWTResponse.
type ParseAuthorizationRequestParams struct {
	// RequestObject is REQUIRED: the raw compact JWS already fetched
	// from request_uri (or otherwise delivered to this Wallet) — this
	// function does no fetching of its own; see its own doc comment
	// for why.
	RequestObject string

	// ClientID is REQUIRED: the "client_id" query parameter this
	// Wallet was invoked with. Checked against both the Request
	// Object's own "client_id" claim and — the only Client Identifier
	// Prefix this function currently supports — the signing
	// certificate's own "x509_hash:..." value (OID4VP §5.6.2).
	ClientID string

	// VerifierTrust decides whether to trust the certificate chain the
	// Request Object is signed with (OID4VP §5.9.3). REQUIRED — pass
	// NoVerifierTrust{} to opt out explicitly.
	VerifierTrust VerifierTrust

	// WalletNonce, when non-empty, is the "wallet_nonce" value this
	// Wallet sent on a POST fetch of request_uri (§5.10) — the
	// Request Object's own "wallet_nonce" claim MUST echo it back
	// (§5.10.1), and ParseAuthorizationRequest enforces that. Leave
	// empty for a plain GET fetch.
	WalletNonce string
}

// AuthorizationRequest is a verified Request Object's own relevant
// claims — the Wallet-side counterpart to
// verifier.BuildAuthorizationRequestResult, returned by
// ParseAuthorizationRequest instead of built by a Verifier.
type AuthorizationRequest struct {
	ClientID    string
	ResponseURI string
	Nonce       string
	State       string
	Query       dcql.Query

	// VerifierCertificate is the Request Object's signing certificate,
	// as ParseAuthorizationRequestParams.VerifierTrust accepted it —
	// e.g. to show the holder who is asking.
	VerifierCertificate *x509.Certificate

	// ResponseEncryptionKey/ResponseEncryptionKeyID are extracted from
	// "client_metadata"'s own "jwks" (§5.1) — a real Verifier only
	// ever sends one genuinely usable key (HAIP's own "one ephemeral
	// response-encryption key per request" shape, see
	// verifier.Config.EncValuesSupported's own doc comment on the
	// building side), but "jwks" is a JWK Set, and RFC 7517 §5 permits
	// (and the OIDF conformance suite's own ignores-unusable-encryption-key
	// module deliberately exercises) additional unrelated/unusable
	// entries a conformant Wallet must skip past — see
	// selectResponseEncryptionKey. Pass both straight through to
	// BuildDirectPostResponseParams.
	ResponseEncryptionKey   *ecdsa.PublicKey
	ResponseEncryptionKeyID string

	// ResponseEncryptionEnc is the JWE "enc" this function picked from
	// the request's own "encrypted_response_enc_values_supported" —
	// A128GCM if offered (HAIP's own minimum every Verifier supports),
	// otherwise whichever the list offers first.
	ResponseEncryptionEnc string
}

// RequestRejectedError is returned by ParseAuthorizationRequest when
// the Request Object is authentic (signature verified, client_id
// matches) but violates a MUST this Wallet won't proceed past —
// currently redirect_uri present alongside response_mode=direct_post
// (OID4VP §8.2: "the Wallet MUST return an invalid_request
// Authorization Response error") and an unrecognized transaction_data
// entry (RFC 9101 semantics: an extension parameter this Wallet
// doesn't understand MUST cause it to refuse, not silently proceed as
// if the parameter weren't there). Unlike a plain error (an invalid
// signature, a client_id that doesn't match at all — see
// ParseAuthorizationRequest's own doc comment), the Request Object's
// authenticity here IS established, so ResponseURI/ResponseEncryptionKey
// are safe to use: a caller can send an OID4VP §8.1 error response
// with them (wallet.BuildDirectPostErrorResponse) instead of only
// rejecting locally. Mirrors verifier.ResponseError's own shape and
// errors.As usage on the Verifier side of this same package family.
type RequestRejectedError struct {
	// Code is the OID4VP/RFC 6749 §5.2 error code to report —
	// currently always "invalid_request".
	Code string

	// Description is a human-readable detail for the error response's
	// own "error_description".
	Description string

	// State/ResponseURI/ResponseEncryptionKey/ResponseEncryptionKeyID/
	// ResponseEncryptionEnc are AuthorizationRequest's own
	// identically-named fields, extracted from the same now-trusted
	// Request Object.
	State                   string
	ResponseURI             string
	ResponseEncryptionKey   *ecdsa.PublicKey
	ResponseEncryptionKeyID string
	ResponseEncryptionEnc   string
}

func (e *RequestRejectedError) Error() string {
	return fmt.Sprintf("wallet: parse authorization request: %s", e.Description)
}

// wireRequestObjectPayload is the Request Object JWS's own payload
// (§5.2) — every member a caller might need, plus two checked only to
// reject: RedirectURI and TransactionData are never acted on (this
// function only ever supports a direct_post(.jwt) response via
// ResponseURI, and recognizes no transaction_data type at all), but
// their presence still causes ParseAuthorizationRequest to refuse the
// request rather than silently ignore them and let a caller proceed —
// confirmed live against the OIDF conformance suite's own
// negative-test-redirect-uri-with-direct-post/
// negative-test-unknown-transaction-data-type modules, which caught
// an earlier version of this logic calling response_uri anyway.
type wireRequestObjectPayload struct {
	ClientID        string            `json:"client_id"`
	ResponseURI     string            `json:"response_uri"`
	RedirectURI     string            `json:"redirect_uri"`
	Nonce           string            `json:"nonce"`
	State           string            `json:"state"`
	DCQLQuery       dcql.Query        `json:"dcql_query"`
	ClientMetadata  json.RawMessage   `json:"client_metadata"`
	TransactionData []json.RawMessage `json:"transaction_data"`
	WalletNonce     string            `json:"wallet_nonce"`
}

type wireClientMetadata struct {
	Jwks struct {
		Keys []json.RawMessage `json:"keys"`
	} `json:"jwks"`
	EncValuesSupported []string `json:"encrypted_response_enc_values_supported"`
}

type wireJWKKid struct {
	Kid string `json:"kid"`
	Use string `json:"use"`
}

// ParseAuthorizationRequest validates the certificate chain in
// params.RequestObject's "x5c" header with params.VerifierTrust (OID4VP
// §5.9.3), verifies the JWS signature against its leaf (RFC9101 §5,
// matching verifier.BuildAuthorizationRequest's own signed-JAR
// convention on the building side), checks that leaf's SHA-256 hash
// matches params.ClientID's own "x509_hash:..." value, and decodes the
// verified payload. When
// params.WalletNonce is non-empty, the returned Request Object's own
// "wallet_nonce" claim MUST echo it back (§5.10.1) — this is checked
// here, not left to the caller, since a missing/mismatched echo means
// the object wasn't actually built fresh for this fetch and processing
// MUST terminate.
//
// This function does no fetching of its own — transport (GET vs. POST
// with a fresh wallet_nonce, §5.10) is the caller's own job, the same
// "protocol logic here, HTTP transport in the caller" split
// verifier.BuildAuthorizationRequest already draws (it doesn't host
// the Request Object it builds either — see that function's own doc
// comment).
//
// Only the "x509_hash" Client Identifier Prefix is supported — the one
// HAIP mandates, and the only one verifier.BuildAuthorizationRequest
// itself produces.
func ParseAuthorizationRequest(params ParseAuthorizationRequestParams) (AuthorizationRequest, error) {
	header, _, err := jose.DecodeUnverified(params.RequestObject)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: decode: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != requestObjectTyp {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: typ = %q, want %q", typ, requestObjectTyp)
	}
	if params.VerifierTrust == nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: VerifierTrust is required (NoVerifierTrust{} opts out explicitly)")
	}
	chain, err := certchain.X5CDERsFromHeader(header)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: %w", err)
	}
	cert, err := params.VerifierTrust.VerifyVerifierChain(chain)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: untrusted verifier: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	wantClientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	if params.ClientID != wantClientID {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: client_id %q does not match x5c leaf's own x509_hash %q", params.ClientID, wantClientID)
	}

	algStr, _ := header["alg"].(string)
	_, payload, err := jose.Verify(jose.Alg(algStr), cert.PublicKey, params.RequestObject)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: signature verification failed: %w", err)
	}

	var wire wireRequestObjectPayload
	if err := json.Unmarshal(payload, &wire); err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: parse payload: %w", err)
	}
	if wire.ClientID != params.ClientID {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: payload client_id %q does not match %q", wire.ClientID, params.ClientID)
	}
	if params.WalletNonce != "" && wire.WalletNonce != params.WalletNonce {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: wallet_nonce claim %q does not match the value sent %q", wire.WalletNonce, params.WalletNonce)
	}

	// client_metadata is parsed here — before the redirect_uri/
	// transaction_data checks below, not after — specifically so
	// ResponseURI/the encryption key are already in hand by the time
	// RequestRejectedError needs to carry them: the Request Object's
	// authenticity is already established above (signature verified,
	// client_id matches), so they're safe to use for those two checks'
	// own error response, unlike for a Request Object that was never
	// authenticated at all.
	var meta wireClientMetadata
	if err := json.Unmarshal(wire.ClientMetadata, &meta); err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: parse client_metadata: %w", err)
	}
	if len(meta.Jwks.Keys) == 0 {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: client_metadata.jwks.keys is empty")
	}
	encPub, kid, err := selectResponseEncryptionKey(meta.Jwks.Keys)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: %w", err)
	}

	enc := "A128GCM"
	if !containsString(meta.EncValuesSupported, enc) && len(meta.EncValuesSupported) > 0 {
		enc = meta.EncValuesSupported[0]
	}

	if wire.RedirectURI != "" {
		return AuthorizationRequest{}, &RequestRejectedError{
			Code:        "invalid_request",
			Description: "redirect_uri must not be present alongside response_uri/direct_post",
			State:       wire.State, ResponseURI: wire.ResponseURI,
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
		}
	}
	if len(wire.TransactionData) > 0 {
		// "invalid_transaction_data", not the generic "invalid_request" —
		// OID4VP §8.5 defines this specific error code for exactly this
		// case (an unrecognized/unsupported transaction_data entry
		// type), confirmed live against a real OIDF conformance suite
		// instance: EnsureInvalidTransactionDataError.java flags
		// "invalid_request" here as its own FAILURE ("'error' field has
		// unexpected value", OID4VP-1FINAL-8.4/8.5), not just a
		// looser-than-ideal but acceptable choice.
		return AuthorizationRequest{}, &RequestRejectedError{
			Code:        "invalid_transaction_data",
			Description: "transaction_data is present but this Wallet recognizes no transaction_data type",
			State:       wire.State, ResponseURI: wire.ResponseURI,
			ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid, ResponseEncryptionEnc: enc,
		}
	}

	return AuthorizationRequest{
		ClientID: params.ClientID, ResponseURI: wire.ResponseURI, Nonce: wire.Nonce, State: wire.State,
		Query: wire.DCQLQuery, VerifierCertificate: cert, ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid,
		ResponseEncryptionEnc: enc,
	}, nil
}

// FetchAuthorizationRequest is ParseAuthorizationRequest's own
// batteries-included counterpart for §5.10's plain GET fetch of
// request_uri — the OID4VP analog of ResolveCredentialOffer (offer.go)
// dereferencing a by-reference Credential Offer, using this Wallet's
// own hardened fetcher (SSRF/size/redirect protection, Config.Fetch)
// the same way. Fetches requestURI, then calls
// ParseAuthorizationRequest with the result, clientID and
// Config.VerifierTrust — which this method therefore requires.
//
// This does NOT cover §5.10's own OPTIONAL POST variant (a Wallet
// sending a fresh "wallet_nonce" so the Verifier can embed it in the
// signed Request Object, §5.10.1): fapihttp.Client — the hardened
// fetcher every other network call in this package uses — only ever
// performs a plain, bodyless GET, by design (see its own doc comment);
// widening it to an arbitrary POST would weaken the SSRF hardening
// every other caller of it relies on. A Wallet that wants the POST
// variant has to perform that request itself (a plain http.Client is
// reasonable here: by this point request_uri is a value this Wallet
// already resolved from an openid4vp:// deep link/QR code, not
// attacker-supplied input the way an initial fetch target can be) and
// call ParseAuthorizationRequest directly with the response body and
// its own WalletNonce — see the package example for the exact shape.
func (w *Wallet) FetchAuthorizationRequest(ctx context.Context, requestURI, clientID string) (AuthorizationRequest, error) {
	if w.cfg.VerifierTrust == nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: fetch authorization request: Config.VerifierTrust is required (NoVerifierTrust{} opts out explicitly)")
	}
	target, err := url.Parse(requestURI)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: fetch authorization request: parse request_uri: %w", err)
	}
	res, err := w.fetcher.Fetch(ctx, fapihttp.FetchRequest{
		URL: target, ExpectedContentType: "application/" + requestObjectTyp,
	})
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: fetch authorization request: fetch request_uri: %w", err)
	}
	return ParseAuthorizationRequest(ParseAuthorizationRequestParams{
		RequestObject: string(res.Body), ClientID: clientID, VerifierTrust: w.cfg.VerifierTrust,
	})
}

// selectResponseEncryptionKey picks the one genuinely usable EC
// response-encryption key out of keys (client_metadata.jwks.keys,
// §5.1) — a real Verifier only ever sends one, but the OIDF
// conformance suite's own ignores-unusable-encryption-key module
// deliberately surrounds it with unparseable decoys (an unrecognized
// key type, and an EC-shaped key with an unsupported/made-up curve)
// specifically to check this: RFC 7517 §5 permits a JWK Set to carry
// members a consumer doesn't understand, which it MUST ignore rather
// than treat as fatal. Any entry that fails to parse as a P-256 EC
// public key, or explicitly declares a "use" other than "enc", is
// skipped; only genuinely running out of candidates is an error.
func selectResponseEncryptionKey(keys []json.RawMessage) (*ecdsa.PublicKey, string, error) {
	for _, raw := range keys {
		var kid wireJWKKid
		if err := json.Unmarshal(raw, &kid); err != nil {
			continue
		}
		if kid.Use != "" && kid.Use != "enc" {
			continue
		}
		rawPub, err := jwk.ParsePublicKey(raw)
		if err != nil {
			continue
		}
		encPub, ok := rawPub.(*ecdsa.PublicKey)
		if !ok {
			continue
		}
		return encPub, kid.Kid, nil
	}
	return nil, "", fmt.Errorf("no usable response-encryption key found in client_metadata.jwks.keys")
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
