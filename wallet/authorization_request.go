package wallet

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/dcql"
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

// ParseAuthorizationRequest verifies params.RequestObject's own JWS
// signature against the leaf certificate its "x5c" header carries
// (RFC9101 §5, matching verifier.BuildAuthorizationRequest's own
// signed-JAR convention on the building side), checks that
// certificate's SHA-256 hash matches params.ClientID's own
// "x509_hash:..." value, and decodes the verified payload. When
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
	x5c := stringSlice(header["x5c"])
	if len(x5c) == 0 {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: missing x5c header")
	}
	der, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: decode x5c[0]: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: parse x5c[0]: %w", err)
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
	if wire.RedirectURI != "" {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: redirect_uri must not be present alongside response_uri/direct_post")
	}
	if len(wire.TransactionData) > 0 {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: transaction_data is present but this Wallet recognizes no transaction_data type")
	}
	if params.WalletNonce != "" && wire.WalletNonce != params.WalletNonce {
		return AuthorizationRequest{}, fmt.Errorf("wallet: parse authorization request: wallet_nonce claim %q does not match the value sent %q", wire.WalletNonce, params.WalletNonce)
	}

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

	return AuthorizationRequest{
		ClientID: params.ClientID, ResponseURI: wire.ResponseURI, Nonce: wire.Nonce, State: wire.State,
		Query: wire.DCQLQuery, ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid,
		ResponseEncryptionEnc: enc,
	}, nil
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

// stringSlice converts a JSON-decoded header value (a []any of
// strings) to []string — matching attestation.stringSlice's own
// unexported shape, kept as a local copy since that one isn't part of
// this repo's public API.
func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
