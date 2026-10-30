package jwk_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwk"
)

// One key has one encoding of each member: a line break (RFC 7515 §2)
// and stray trailing bits (RFC 4648 §3.5) are refused, so neither can
// give one key a second thumbprint or a second matching JWK.
func TestThumbprint_NonCanonicalEncodings(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonical.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	// 32 bytes is 43 base64url characters, the last carrying 2 unused
	// bits: flip one.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.Index(alphabet, canonical.X[42:])
	variants := map[string]jwk.JWK{
		"trailing bits": {Kty: "EC", Crv: "P-256", X: canonical.X[:42] + string(alphabet[last^1]), Y: canonical.Y},
		"a line break":  {Kty: "EC", Crv: "P-256", X: canonical.X[:20] + "\n" + canonical.X[20:], Y: canonical.Y},
	}
	for name, v := range variants {
		if _, err := v.PublicKey(); err == nil {
			t.Errorf("%s: PublicKey accepted a non-canonical x encoding", name)
		}
		if got, _ := v.Thumbprint(); got == want {
			t.Errorf("%s: thumbprint is the key's own", name)
		}
		raw, _ := json.Marshal(v)
		if ok, _ := jwk.Matches(raw, &key.PublicKey); ok {
			t.Errorf("%s: Matches accepted it as the key", name)
		}
	}
}
