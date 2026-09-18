package statuslist

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// FuzzVerifyToken exercises VerifyToken against arbitrary strings — a
// Status List Token is fetched from a URI a Referenced Token's own
// "status" claim names (draft-12 §5.1), so it's attacker-influenced
// wire data (a malicious/compromised status list endpoint) parsed and
// signature-checked before the statuses inside it are trusted.
func FuzzVerifyToken(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	sl, err := New(Bits1, []uint8{0, 1, 1, 0}, "")
	if err != nil {
		f.Fatalf("New(StatusList): %v", err)
	}
	valid, err := IssueToken(key, jose.ES256, TokenClaims{
		Sub: "https://example.com/statuslists/1", Iat: 1767225600, StatusList: sl,
	}, "fuzz-kid")
	if err != nil {
		f.Fatalf("IssueToken: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c")

	f.Fuzz(func(t *testing.T, token string) {
		_, _ = VerifyToken(token, &key.PublicKey, jose.ES256, VerifyOptions{})
	})
}
