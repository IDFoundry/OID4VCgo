package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FuzzDecodeUnverified exercises DecodeUnverified/Verify against
// arbitrary strings — the entry point every caller in this module goes
// through to split and base64url-decode a compact JWS before any
// signature is checked (DecodeUnverified's own doc comment: reading a
// "kid"/"x5c" to resolve a verification key in the first place). A
// value DecodeUnverified accepts must also survive a Verify call
// without panicking, whether or not the signature actually checks out
// — that's the one property this target checks beyond "does not
// crash".
func FuzzDecodeUnverified(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := Sign(ES256, key, map[string]any{"kid": "fuzz-kid"}, []byte(`{"hello":"world"}`))
	if err != nil {
		f.Fatalf("sign: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("a.b.c")
	f.Add("a.b.c.d")
	f.Add(valid + ".")
	f.Add(valid[:len(valid)-1])
	f.Add("eyJhbGciOiJub25lIn0.e30.")
	f.Add("!!!.!!!.!!!")

	f.Fuzz(func(t *testing.T, s string) {
		if _, _, err := DecodeUnverified(s); err != nil {
			return
		}
		_, _, _ = Verify(ES256, &key.PublicKey, s)
	})
}
