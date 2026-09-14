package jose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
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

	tampered := compact[:len(compact)-1] + "x"
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
