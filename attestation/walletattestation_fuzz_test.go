package attestation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzParseWalletAttestationClaims exercises
// ParseWalletAttestationClaims against arbitrary strings — a Wallet
// Attestation JWT is client-supplied wire data, and this function
// deliberately reads its payload without checking the signature (see
// its own doc comment), so it must tolerate anything the fuzzer
// produces without panicking.
func FuzzParseWalletAttestationClaims(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}

	minimal, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign minimal: %v", err)
	}
	full, err := jose.Sign(jose.ES256, key, map[string]any{"typ": WalletAttestationTypHeader},
		[]byte(`{"wallet_name":"Fuzz Wallet","wallet_link":"https://wallet.example","status":{"status_list":{"idx":0,"uri":"https://example.com/statuslist"}}}`))
	if err != nil {
		f.Fatalf("sign full: %v", err)
	}
	wrongType, err := jose.Sign(jose.ES256, key, map[string]any{"typ": "not-a-wallet-attestation"}, []byte(`{}`))
	if err != nil {
		f.Fatalf("sign wrong-type: %v", err)
	}

	f.Add(minimal)
	f.Add(full)
	f.Add(wrongType)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, compact string) {
		_, _ = ParseWalletAttestationClaims(compact)
	})
}
