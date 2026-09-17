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
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("wallet: build direct_post response: marshal body: %w", err)
	}

	responseJWE, err := jwe.Encrypt(params.EncryptionKey, jwe.Enc(params.EncryptionEnc), bodyJSON, jwe.EncryptOptions{KeyID: params.EncryptionKeyID})
	if err != nil {
		return "", fmt.Errorf("wallet: build direct_post response: encrypt: %w", err)
	}
	return responseJWE, nil
}
