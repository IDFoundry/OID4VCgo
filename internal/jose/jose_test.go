package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestSignVerifyES256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := Sign(ES256, key, map[string]any{"typ": "test+jwt"}, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	header, got, err := Verify(ES256, &key.PublicKey, compact)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
	if header["typ"] != "test+jwt" {
		t.Errorf("typ header = %v, want test+jwt", header["typ"])
	}
	if header["alg"] != "ES256" {
		t.Errorf("alg header = %v, want ES256", header["alg"])
	}
}

func TestSignVerifyEdDSA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	payload := []byte(`{"hello":"world"}`)

	compact, err := Sign(EdDSA, priv, nil, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	_, got, err := Verify(EdDSA, pub, compact)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("payload = %s, want %s", got, payload)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Flip a character early in the signature segment, not the last
	// one: a fixed-width R||S signature's final base64url character
	// can carry unused padding bits (64 bytes % 3 == 1, so the last
	// char only encodes the top 2 of its 6 bits), so changing only
	// that character can legally decode to the same bytes and this
	// test would pass for the wrong reason.
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact JWS has %d parts, want 3", len(parts))
	}
	sig := []rune(parts[2])
	if sig[0] == 'x' {
		sig[0] = 'y'
	} else {
		sig[0] = 'x'
	}
	parts[2] = string(sig)
	tampered := strings.Join(parts, ".")
	if tampered == compact {
		t.Fatalf("tamper produced identical string")
	}
	if _, _, err := Verify(ES256, &key.PublicKey, tampered); err == nil {
		t.Errorf("Verify accepted a tampered signature")
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	key1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key1, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := Verify(ES256, &key2.PublicKey, compact); err == nil {
		t.Errorf("Verify accepted a signature under the wrong key")
	}
}

func TestVerifyRejectsAlgMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, nil, []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := Verify(EdDSA, &key.PublicKey, compact); err == nil {
		t.Errorf("Verify accepted a JWS whose header alg does not match the requested alg")
	}
}

func TestDecodeUnverified(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	compact, err := Sign(ES256, key, map[string]any{"kid": "k1"}, []byte(`{"iss":"issuer"}`))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	header, payload, err := DecodeUnverified(compact)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	if header["kid"] != "k1" {
		t.Errorf("kid = %v, want k1", header["kid"])
	}
	if string(payload) != `{"iss":"issuer"}` {
		t.Errorf("payload = %s", payload)
	}
}
