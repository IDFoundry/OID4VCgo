package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/dpop"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// FuzzVerifyDPoPProof exercises Verify against arbitrary DPoP proof
// strings — attacker-controlled per request, and self-signed (the
// verification key comes from the proof's own embedded "jwk" header,
// not an external source), so a malicious proof only has to convince
// this package, not impersonate a registered key. Method/URL/Now are
// fixed to a realistic request so the fuzzer's mutations land on the
// one field that's actually untrusted. Only checks for panics/hangs.
func FuzzVerifyDPoPProof(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	pubJWK, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		f.Fatalf("jwk.Marshal: %v", err)
	}
	const method = "POST"
	const htu = "https://issuer.example.com/token"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	sign := func(claims string) string {
		proof, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt", "jwk": pubJWK}, []byte(claims))
		if err != nil {
			f.Fatalf("sign: %v", err)
		}
		return proof
	}

	minimal := sign(`{"jti":"fuzz-jti-1","htm":"POST","htu":"https://issuer.example.com/token","iat":1767225600}`)
	withNonce := sign(`{"jti":"fuzz-jti-2","htm":"POST","htu":"https://issuer.example.com/token","iat":1767225600,"nonce":"fuzz-nonce"}`)
	noJWK, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "dpop+jwt"}, []byte(`{"jti":"x","htm":"POST","htu":"https://issuer.example.com/token","iat":1767225600}`))
	if err != nil {
		f.Fatalf("sign no-jwk proof: %v", err)
	}
	wrongType, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "not-dpop+jwt", "jwk": pubJWK}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type proof: %v", err)
	}

	f.Add(minimal)
	f.Add(withNonce)
	f.Add(noJWK)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, proof string) {
		_, _ = dpop.Verify(context.Background(), dpop.VerifyRequest{
			Proof: proof, Method: method, URL: htu,
			Now: now, MaxProofAge: time.Hour, RequiredNonce: "fuzz-nonce",
			Replay: fuzzReplayChecker{},
		})
	})
}

// fuzzReplayChecker never rejects — this target fuzzes proof parsing
// and claim validation, not replay-store behavior, which real
// implementations (memstore, etc.) already have their own unit tests
// for.
type fuzzReplayChecker struct{}

func (fuzzReplayChecker) UseOnce(context.Context, string, time.Time) error { return nil }
