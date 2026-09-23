package wallet

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// BuildDirectPostResponseParams is the input to BuildDirectPostResponse.
type BuildDirectPostResponseParams struct {
	// VPToken is REQUIRED: PresentCredentials' own return value —
	// {<Credential Query id>: [<Presentation>]}.
	VPToken map[string][]string

	// State is OPTIONAL: echo AuthorizationRequest.State back when the
	// Verifier's own Request Object carried one (§5.3).
	State string

	// EncryptionKey/EncryptionKeyID/EncryptionEnc name the Verifier's
	// own response-encryption key — pass
	// AuthorizationRequest.ResponseEncryptionKey/
	// ResponseEncryptionKeyID/ResponseEncryptionEnc straight through.
	// All REQUIRED: HAIP's own redirect-flow response_mode
	// ("direct_post.jwt") always encrypts.
	EncryptionKey   *ecdsa.PublicKey
	EncryptionKeyID string
	EncryptionEnc   string
}

// BuildDirectPostResponse builds and encrypts a direct_post.jwt
// response body (§8.1) — the "response" form parameter's own value a
// caller POSTs to the Verifier's own response_uri. Mirrors
// verifier.ParseDirectPostJWTResponse's own decrypt-and-parse, on the
// building side: this function does no POSTing of its own, the same
// "protocol logic here, HTTP transport in the caller" split
// ParseAuthorizationRequest already draws.
func BuildDirectPostResponse(params BuildDirectPostResponseParams) (string, error) {
	if len(params.VPToken) == 0 {
		return "", fmt.Errorf("wallet: build direct_post response: vp_token is required")
	}
	if params.EncryptionKey == nil {
		return "", fmt.Errorf("wallet: build direct_post response: encryption_key is required")
	}

	body := map[string]any{"vp_token": params.VPToken}
	if params.State != "" {
		body["state"] = params.State
	}
	return encryptDirectPostBody(body, params.EncryptionKey, params.EncryptionKeyID, params.EncryptionEnc)
}

// BuildDirectPostErrorResponseParams is the input to
// BuildDirectPostErrorResponse.
type BuildDirectPostErrorResponseParams struct {
	// Error is REQUIRED: the response's own "error" value (RFC 6749
	// §5.2 error codes, extended by this specification's own — e.g.
	// "access_denied", "invalid_request").
	Error string

	// ErrorDescription is OPTIONAL: the response's own
	// "error_description".
	ErrorDescription string

	// State is OPTIONAL: echo AuthorizationRequest.State back when the
	// Verifier's own Request Object carried one (§5.3).
	State string

	// EncryptionKey/EncryptionKeyID/EncryptionEnc name the Verifier's
	// own response-encryption key — see
	// BuildDirectPostResponseParams' own doc comment; the same
	// requirement applies here.
	EncryptionKey   *ecdsa.PublicKey
	EncryptionKeyID string
	EncryptionEnc   string
}

// BuildDirectPostErrorResponse builds and encrypts a direct_post.jwt
// error response body (§8.1) — sent instead of BuildDirectPostResponse's
// own vp_token when the Wallet can't or won't satisfy the Authorization
// Request (e.g. no matching credential, a required parameter it can't
// provide), but only once the Request Object itself has already been
// verified legitimate: a Wallet that never got that far (an invalid
// signature, an untrusted client_id) has no trustworthy response_uri to
// send anything to yet and should reject locally instead of contacting
// one — see cmd/conformance-wallet-vp/handlers.go's own handleAuthorize
// for that exact distinction applied live (only a wallet.PresentCredentials
// failure — after fetchAndVerifyRequestObject already succeeded — sends
// one of these; a Request Object validation failure never does).
// Mirrors verifier.ParseDirectPostJWTResponse's own *ResponseError
// parsing, on the building side.
func BuildDirectPostErrorResponse(params BuildDirectPostErrorResponseParams) (string, error) {
	if params.Error == "" {
		return "", fmt.Errorf("wallet: build direct_post error response: error is required")
	}
	if params.EncryptionKey == nil {
		return "", fmt.Errorf("wallet: build direct_post error response: encryption_key is required")
	}

	body := map[string]any{"error": params.Error}
	if params.ErrorDescription != "" {
		body["error_description"] = params.ErrorDescription
	}
	if params.State != "" {
		body["state"] = params.State
	}
	return encryptDirectPostBody(body, params.EncryptionKey, params.EncryptionKeyID, params.EncryptionEnc)
}

// encryptDirectPostBody marshals body and encrypts it the same way for
// both BuildDirectPostResponse and BuildDirectPostErrorResponse — the
// two differ only in what body itself contains.
func encryptDirectPostBody(body map[string]any, encryptionKey *ecdsa.PublicKey, encryptionKeyID, encryptionEnc string) (string, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("wallet: build direct_post response: marshal body: %w", err)
	}
	responseJWE, err := jwe.Encrypt(encryptionKey, jwe.Enc(encryptionEnc), bodyJSON, jwe.EncryptOptions{KeyID: encryptionKeyID})
	if err != nil {
		return "", fmt.Errorf("wallet: build direct_post response: encrypt: %w", err)
	}
	return responseJWE, nil
}
