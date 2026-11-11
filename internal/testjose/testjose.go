// Package testjose signs compact JWSs with ES384 and ES512, which
// internal/jose verifies but never signs with, for tests of the code
// that verifies them. It is its own ECDSA JWS signer (RFC 7515, RFC
// 7518 §3.4), not internal/jose's, so a test of jose.Verify isn't
// checking jose against itself. It also signs a header naming one
// algorithm with a key on another curve, for tests that such a JWS is
// refused.
package testjose

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/ecdsafixed"
)

// Sign returns the compact JWS of payload under header, its "alg" set
// to alg ("ES256", "ES384" or "ES512"), signed by key with alg's
// digest. The signature's R and S each take key's own curve size,
// whatever alg names, so a mismatched pair is still a well-formed JWS.
func Sign(t testing.TB, alg string, key *ecdsa.PrivateKey, header map[string]any, payload []byte) string {
	t.Helper()
	h := map[string]any{}
	for k, v := range header {
		h[k] = v
	}
	h["alg"] = alg
	headerJSON, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("testjose: marshal header: %v", err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(payload)
	der, err := ecdsa.SignASN1(rand.Reader, key, digest(t, alg, []byte(input)))
	if err != nil {
		t.Fatalf("testjose: sign: %v", err)
	}
	sig, err := ecdsafixed.ToFixed(der, (key.Curve.Params().BitSize+7)/8)
	if err != nil {
		t.Fatalf("testjose: sign: %v", err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// SignClaims is Sign with claims marshaled as the payload.
func SignClaims(t testing.TB, alg string, key *ecdsa.PrivateKey, header map[string]any, claims any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("testjose: marshal claims: %v", err)
	}
	return Sign(t, alg, key, header, payload)
}

func digest(t testing.TB, alg string, b []byte) []byte {
	t.Helper()
	switch alg {
	case "ES256":
		sum := sha256.Sum256(b)
		return sum[:]
	case "ES384":
		sum := sha512.Sum384(b)
		return sum[:]
	case "ES512":
		sum := sha512.Sum512(b)
		return sum[:]
	}
	t.Fatalf("testjose: unsupported alg %q", alg)
	return nil
}
