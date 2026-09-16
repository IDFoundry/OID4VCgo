package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
)

// walletNonceEntropyBytes matches this repo's own nonce-generation
// convention elsewhere (e.g. cmd/conformance-verifier's own session
// IDs, verifier's own Authorization Request "nonce") — 256 bits,
// base64url-encoded.
const walletNonceEntropyBytes = 32

// newWalletNonce generates a fresh, cryptographically random
// "wallet_nonce" value (OID4VP §5.10: "a fresh, cryptographically
// random number with sufficient entropy") for one POST fetch of
// request_uri.
func newWalletNonce() (string, error) {
	buf := make([]byte, walletNonceEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// walletMetadataForPost is this binary's own "wallet_metadata" value
// (OID4VP §10/§5.10) sent on a POST request_uri fetch — an accurate,
// minimal declaration of the one presentation format/algorithm this
// binary actually supports (dc+sd-jwt, ES256 for both the Issuer
// signature and the Key Binding JWT — see wallet.HeldCredential's own
// HolderKeyAlg in credential.go), not a placeholder.
const walletMetadataForPost = `{"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"],"kb-jwt_alg_values":["ES256"]}}}`

// authorizationRequest is a verified Authorization Request's own
// relevant claims (§5.2) — this binary only ever receives the
// x509_hash-prefixed, signed-JAR shape verifier.BuildAuthorizationRequest
// itself builds, matching the one HAIP wallet plan variant this binary
// targets (request_uri_signed, x509_hash) — see requestobject.go's own
// package-level notes in conformance/wallet-vp/README.md for the DC
// API/other-client_id-prefix variants this doesn't cover.
type authorizationRequest struct {
	ClientID    string
	ResponseURI string
	Nonce       string
	State       string
	Query       dcql.Query

	// ResponseEncryptionKey/ResponseEncryptionKeyID are extracted from
	// "client_metadata"'s own "jwks" — this binary always finds
	// exactly one entry and uses it, matching HAIP's own "one
	// ephemeral response-encryption key per request" shape (see
	// verifier.Config.EncValuesSupported's own doc comment on the
	// building side).
	ResponseEncryptionKey   *ecdsa.PublicKey
	ResponseEncryptionKeyID string

	// ResponseEncryptionEnc is the JWE "enc" this binary picked from
	// the request's own "encrypted_response_enc_values_supported" —
	// A128GCM if offered (HAIP's own minimum every Verifier supports,
	// see verifier.Config.EncValuesSupported's own doc comment),
	// otherwise whatever the Verifier's own list offers first.
	ResponseEncryptionEnc string
}

// wireRequestObjectPayload is the Request Object JWS's own payload
// (§5.2) — every member this binary actually reads, plus two it only
// reads to reject: RedirectURI and TransactionData are never acted on
// (this binary only ever builds a direct_post.jwt response via
// ResponseURI, and recognizes no transaction_data type at all), but
// their presence must still cause fetchAndVerifyRequestObject to
// refuse the request rather than silently ignore them and proceed —
// confirmed live against the OIDF conformance suite's own
// negative-test-redirect-uri-with-direct-post/
// negative-test-unknown-transaction-data-type modules, which caught
// this binary calling response_uri anyway.
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
}

// fetchAndVerifyRequestObject fetches requestURI — via POST (with a
// fresh wallet_nonce, §5.10) when usePost is true, plain GET (§5)
// otherwise — verifies the returned JWS against the leaf certificate
// its own "x5c" header carries (RFC9101 §5, this repo's own
// signed-JAR convention — see verifier.BuildAuthorizationRequest's own
// doc comment for the building side), checks that certificate's
// SHA-256 hash matches clientID's own "x509_hash:..." value, and
// decodes the verified payload. When usePost sent a wallet_nonce, the
// returned Request Object's own "wallet_nonce" claim MUST echo it back
// (§5.10.1) — this is checked here, not left to the caller, since a
// missing/mismatched echo means the object wasn't actually built fresh
// for this fetch and processing MUST terminate.
func fetchAndVerifyRequestObject(requestURI, clientID string, usePost bool) (authorizationRequest, error) {
	var compact, walletNonce string
	var err error
	if usePost {
		walletNonce, err = newWalletNonce()
		if err != nil {
			return authorizationRequest{}, fmt.Errorf("generate wallet_nonce: %w", err)
		}
		form := url.Values{"wallet_nonce": {walletNonce}, "wallet_metadata": {walletMetadataForPost}}
		compact, err = httpPostFormString(requestURI, form)
		if err != nil {
			return authorizationRequest{}, fmt.Errorf("fetch request_uri via POST: %w", err)
		}
	} else {
		compact, err = httpGetString(requestURI)
		if err != nil {
			return authorizationRequest{}, fmt.Errorf("fetch request_uri: %w", err)
		}
	}

	header, _, err := jose.DecodeUnverified(compact)
	if err != nil {
		return authorizationRequest{}, fmt.Errorf("decode request object: %w", err)
	}
	if typ, _ := header["typ"].(string); typ != "oauth-authz-req+jwt" {
		return authorizationRequest{}, fmt.Errorf("request object: typ = %q, want \"oauth-authz-req+jwt\"", typ)
	}
	x5c := stringSlice(header["x5c"])
	if len(x5c) == 0 {
		return authorizationRequest{}, fmt.Errorf("request object: missing x5c header")
	}
	der, err := base64.StdEncoding.DecodeString(x5c[0])
	if err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: decode x5c[0]: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: parse x5c[0]: %w", err)
	}

	hash := sha256.Sum256(cert.Raw)
	wantClientID := "x509_hash:" + base64.RawURLEncoding.EncodeToString(hash[:])
	if clientID != wantClientID {
		return authorizationRequest{}, fmt.Errorf("request object: client_id %q does not match x5c leaf's own x509_hash %q", clientID, wantClientID)
	}

	algStr, _ := header["alg"].(string)
	_, payload, err := jose.Verify(jose.Alg(algStr), cert.PublicKey, compact)
	if err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: signature verification failed: %w", err)
	}

	var wire wireRequestObjectPayload
	if err := json.Unmarshal(payload, &wire); err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: parse payload: %w", err)
	}
	if wire.ClientID != clientID {
		return authorizationRequest{}, fmt.Errorf("request object: payload client_id %q does not match %q", wire.ClientID, clientID)
	}
	if wire.RedirectURI != "" {
		return authorizationRequest{}, fmt.Errorf("request object: redirect_uri must not be present alongside response_uri/direct_post")
	}
	if len(wire.TransactionData) > 0 {
		return authorizationRequest{}, fmt.Errorf("request object: transaction_data is present but this wallet recognizes no transaction_data type")
	}
	if walletNonce != "" && wire.WalletNonce != walletNonce {
		return authorizationRequest{}, fmt.Errorf("request object: wallet_nonce claim %q does not match the value sent %q", wire.WalletNonce, walletNonce)
	}

	var meta wireClientMetadata
	if err := json.Unmarshal(wire.ClientMetadata, &meta); err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: parse client_metadata: %w", err)
	}
	if len(meta.Jwks.Keys) == 0 {
		return authorizationRequest{}, fmt.Errorf("request object: client_metadata.jwks.keys is empty")
	}
	var kid wireJWKKid
	if err := json.Unmarshal(meta.Jwks.Keys[0], &kid); err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: parse client_metadata.jwks.keys[0]: %w", err)
	}
	rawPub, err := jwk.ParsePublicKey(meta.Jwks.Keys[0])
	if err != nil {
		return authorizationRequest{}, fmt.Errorf("request object: parse client_metadata response-encryption key: %w", err)
	}
	encPub, ok := rawPub.(*ecdsa.PublicKey)
	if !ok {
		return authorizationRequest{}, fmt.Errorf("request object: client_metadata response-encryption key is %T, want *ecdsa.PublicKey", rawPub)
	}

	enc := "A128GCM"
	if !containsString(meta.EncValuesSupported, enc) && len(meta.EncValuesSupported) > 0 {
		enc = meta.EncValuesSupported[0]
	}

	return authorizationRequest{
		ClientID: clientID, ResponseURI: wire.ResponseURI, Nonce: wire.Nonce, State: wire.State,
		Query: wire.DCQLQuery, ResponseEncryptionKey: encPub, ResponseEncryptionKeyID: kid.Kid,
		ResponseEncryptionEnc: enc,
	}, nil
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
// strings) to []string, matching attestation.stringSlice's own
// unexported shape — kept as a local copy since that one isn't part
// of this repo's public API.
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
