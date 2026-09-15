package verifier

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"

	"github.com/idfoundry/oid4vcigo/internal/jwe"
)

// ResponseError is a Wallet's own error response (§8.1) — sent instead
// of a vp_token, e.g. when it can't satisfy the Authorization
// Request's own dcql_query.
type ResponseError struct {
	// Code is the response's own "error" value (RFC 6749 §5.2 error
	// codes, extended by this specification's own — e.g.
	// "access_denied", "invalid_request").
	Code string

	// Description is the response's own "error_description", if any.
	Description string

	// State is the response's own "state", when present — the same
	// value BuildAuthorizationRequestRequest.State carried, if any.
	State string
}

func (e *ResponseError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("verifier: wallet returned error %q: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("verifier: wallet returned error %q", e.Code)
}

// ParsedResponse is a direct_post.jwt response's own decrypted payload
// (§8.1).
type ParsedResponse struct {
	// VPToken maps each dcql.CredentialQuery.ID to the Presentation(s)
	// matched against it — a compact SD-JWT+KB string for "dc+sd-jwt",
	// a base64url-encoded DeviceResponse for "mso_mdoc" (not yet
	// supported by VerifyResponse — see the package doc comment). A
	// Credential Query with no match at all (legal only when it's
	// non-required) has no entry here (§8.1's own "omit the key
	// entirely" rule).
	VPToken map[string][]string

	// State is the response's own "state", when present.
	State string
}

// ParseDirectPostJWTResponse decrypts responseJWE — the direct_post.jwt
// response's own "response" form parameter — using decryptionKey (the
// ResponseDecryptionKey a prior BuildAuthorizationRequest call
// returned for this same request) and parses the resulting plaintext
// per §8.1. Returns a *ResponseError when the Wallet reported an error
// instead of a vp_token.
func (v *Verifier) ParseDirectPostJWTResponse(responseJWE string, decryptionKey *ecdsa.PrivateKey) (ParsedResponse, error) {
	plaintext, err := jwe.Decrypt(decryptionKey, responseJWE)
	if err != nil {
		return ParsedResponse{}, fmt.Errorf("verifier: parse direct_post.jwt response: decrypt: %w", err)
	}

	var wire struct {
		VPToken          map[string][]string `json:"vp_token"`
		State            string              `json:"state"`
		Error            string              `json:"error"`
		ErrorDescription string              `json:"error_description"`
	}
	if err := json.Unmarshal(plaintext, &wire); err != nil {
		return ParsedResponse{}, fmt.Errorf("verifier: parse direct_post.jwt response: unmarshal: %w", err)
	}
	if wire.Error != "" {
		return ParsedResponse{}, &ResponseError{Code: wire.Error, Description: wire.ErrorDescription, State: wire.State}
	}
	if len(wire.VPToken) == 0 {
		return ParsedResponse{}, fmt.Errorf("verifier: parse direct_post.jwt response: vp_token is missing or empty")
	}
	return ParsedResponse{VPToken: wire.VPToken, State: wire.State}, nil
}
