package jwk

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"
)

// FuzzParsePublicKey exercises ParsePublicKey against arbitrary bytes
// — the entry point that turns untrusted wire data (a JWK embedded in
// a DPoP proof header, client_metadata.jwks, or a fetched JWK Set)
// into a usable public key. Only checks for panics/hangs: ParsePublicKey
// is expected to reject almost everything the fuzzer generates, so
// there is no useful oracle beyond "never crashes, never loops".
func FuzzParsePublicKey(f *testing.F) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate ecdsa key: %v", err)
	}
	ecJWK, err := Marshal(&ecKey.PublicKey)
	if err != nil {
		f.Fatalf("Marshal(ec): %v", err)
	}
	ecData, err := json.Marshal(ecJWK)
	if err != nil {
		f.Fatalf("marshal ec jwk: %v", err)
	}

	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatalf("generate ed25519 key: %v", err)
	}
	edJWK, err := Marshal(edPriv.Public())
	if err != nil {
		f.Fatalf("Marshal(ed25519): %v", err)
	}
	edData, err := json.Marshal(edJWK)
	if err != nil {
		f.Fatalf("marshal ed25519 jwk: %v", err)
	}

	f.Add(ecData)
	f.Add(edData)
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"kty":"EC","crv":"P-256","x":"","y":""}`))
	f.Add([]byte(`{"kty":"OKP","crv":"Ed25519","x":"AQ"}`))
	f.Add([]byte(`{"kty":"RSA","n":"AQAB","e":"AQAB"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParsePublicKey(data)
	})
}
