package verifier_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// FuzzParseDirectPostJWTResponse exercises ParseDirectPostJWTResponse
// against arbitrary strings — the Verifier's own entry point for a
// Wallet's Authorization Response (§8.1), the single most directly
// attacker-facing boundary this repo's Verifier role has: any Wallet,
// honest or malicious, presents data here before the Verifier has any
// basis to trust it. Fixes the decryption key so only the compact JWE
// string itself varies. Only checks for panics/hangs.
func FuzzParseDirectPostJWTResponse(f *testing.F) {
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate signer key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fuzz verifier"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &signerKey.PublicKey, signerKey)
	if err != nil {
		f.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		f.Fatalf("ParseCertificate: %v", err)
	}
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example.com/response")
	if err != nil {
		f.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  cert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{}},
	}, verifier.Dependencies{Signer: signerKey, Random: rand.Reader})
	if err != nil {
		f.Fatalf("verifier.New: %v", err)
	}

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
