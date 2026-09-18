package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// FuzzDecrypt exercises Decrypt against arbitrary compact-JWE strings —
// a Credential Request's own "credential_response_encryption" JWE (§10)
// arrives encrypted to this issuer's own key but is otherwise entirely
// attacker-controlled: header, ephemeral public key, IV, ciphertext and
// tag are all wire data parsed before any AEAD check runs. Fixes the
// recipient key so only the compact string itself varies. Only checks
// for panics/hangs.
func FuzzDecrypt(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}

	plain, err := Encrypt(&key.PublicKey, A128GCM, []byte(`{"hello":"world"}`), EncryptOptions{KeyID: "fuzz-kid"})
	if err != nil {
		f.Fatalf("encrypt(plain): %v", err)
	}
	zipped, err := Encrypt(&key.PublicKey, A256GCM, []byte(`{"hello":"world, but longer and more compressible, repeat repeat repeat"}`), EncryptOptions{Zip: DEF})
	if err != nil {
		f.Fatalf("encrypt(zipped): %v", err)
	}

	f.Add(plain)
	f.Add(zipped)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c.d.e")
	f.Add(plain + ".")
	f.Add(plain[:len(plain)-1])
	f.Add("eyJhbGciOiJub25lIn0...e30.")

	f.Fuzz(func(t *testing.T, compact string) {
		_, _ = Decrypt(key, compact)
	})
}

// FuzzDecodeHeader exercises DecodeHeader against arbitrary
// compact-JWE-shaped strings — used to read "kid"/"alg" before a
// recipient key has been resolved, so it must tolerate a header from
// an untrusted or malformed JWE without panicking.
func FuzzDecodeHeader(f *testing.F) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatalf("generate key: %v", err)
	}
	valid, err := Encrypt(&key.PublicKey, A128GCM, []byte("hi"), EncryptOptions{KeyID: "fuzz-kid"})
	if err != nil {
		f.Fatalf("encrypt: %v", err)
	}

	f.Add(valid)
	f.Add("")
	f.Add(".")
	f.Add("a.b.c.d.e")
	f.Add("!!!...")

	f.Fuzz(func(t *testing.T, compact string) {
		_, _ = DecodeHeader(compact)
	})
}
