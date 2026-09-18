package verifier_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testverifier"
)

// FuzzParseDirectPostJWTResponse exercises ParseDirectPostJWTResponse
// against arbitrary strings — the Verifier's own entry point for a
// Wallet's Authorization Response (§8.1), the single most directly
// attacker-facing boundary this repo's Verifier role has: any Wallet,
// honest or malicious, presents data here before the Verifier has any
// basis to trust it. Fixes the decryption key so only the compact JWE
// string itself varies. Only checks for panics/hangs.
func FuzzParseDirectPostJWTResponse(f *testing.F) {
	v := testverifier.New(f)

	decryptionKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate decryption key: %v", err)
	}

	vpTokenBody, err := json.Marshal(map[string]any{
		"vp_token": map[string][]string{"identity_credential": {"fuzz-sdjwt-compact-string"}},
		"state":    "fuzz-state",
	})
	if err != nil {
		f.Fatalf("marshal vp_token body: %v", err)
	}
	vpToken, err := jwe.Encrypt(&decryptionKey.PublicKey, jwe.A128GCM, vpTokenBody, jwe.EncryptOptions{})
	if err != nil {
		f.Fatalf("encrypt vp_token: %v", err)
	}

	errorBody, err := json.Marshal(map[string]any{
		"error": "access_denied", "error_description": "fuzz decline", "state": "fuzz-state",
	})
	if err != nil {
		f.Fatalf("marshal error body: %v", err)
	}
	errorResponse, err := jwe.Encrypt(&decryptionKey.PublicKey, jwe.A128GCM, errorBody, jwe.EncryptOptions{})
	if err != nil {
		f.Fatalf("encrypt error response: %v", err)
	}

	f.Add(vpToken)
	f.Add(errorResponse)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c.d.e")

	f.Fuzz(func(t *testing.T, responseJWE string) {
		_, _ = v.ParseDirectPostJWTResponse(responseJWE, decryptionKey)
	})
}
