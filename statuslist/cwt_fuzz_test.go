package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// FuzzVerifyTokenCWT exercises VerifyTokenCWT against arbitrary bytes
// — the CWT-format counterpart of FuzzVerifyToken, same attacker
// model (a fetched, potentially malicious status list endpoint), CBOR
// wire data instead of a compact JWT.
func FuzzVerifyTokenCWT(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	sl, err := New(Bits1, []uint8{0, 1, 1, 0}, "")
	if err != nil {
		f.Fatalf("New(StatusList): %v", err)
	}
	valid, err := IssueTokenCWT(key, cose.ES256, TokenClaims{
		Sub: "https://example.com/statuslists/1", Iat: 1767225600, StatusList: sl,
	}, []byte("fuzz-kid"))
	if err != nil {
		f.Fatalf("IssueTokenCWT: %v", err)
	}

	f.Add(valid)
	f.Add([]byte{})
	f.Add([]byte{0xa0})
	f.Add(valid[:len(valid)-1])

	f.Fuzz(func(t *testing.T, token []byte) {
		_, _ = VerifyTokenCWT(token, &key.PublicKey, cose.ES256, VerifyOptions{})
	})
}
