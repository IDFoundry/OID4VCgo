package verifier

import (
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// ResponseKeyID returns the "kid" in an encrypted Authorization
// Response's JWE protected header (direct_post.jwt, OID4VP §8.3), read
// without decrypting it — the value a Verifier with several requests
// open matches against each request's
// BuildAuthorizationRequestResult.ResponseEncryptionKeyID to find which
// request (and decryption key) the response belongs to, since its
// "state" is only readable after decryption.
//
// The kid is unauthenticated: it only selects a decryption key.
// ParseDirectPostJWTResponse with that key, and VerifyResponse, still
// decide whether the response is genuine.
func ResponseKeyID(responseJWE string) (string, error) {
	header, err := jwe.DecodeHeader(responseJWE)
	if err != nil {
		return "", fmt.Errorf("verifier: response key id: %w", err)
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return "", fmt.Errorf("verifier: response key id: the JWE header has no kid")
	}
	return kid, nil
}
