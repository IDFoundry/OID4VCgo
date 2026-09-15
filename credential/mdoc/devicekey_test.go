package mdoc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestCoseKeyRoundTripEC2(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	coseKey, err := NewCoseKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("NewCoseKey: %v", err)
	}
	got, err := coseKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	pub, ok := got.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Errorf("PublicKey = %v, want %v", got, &key.PublicKey)
	}
}

func TestCoseKeyRoundTripOKP(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	coseKey, err := NewCoseKey(pub)
	if err != nil {
		t.Fatalf("NewCoseKey: %v", err)
	}
	got, err := coseKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	edPub, ok := got.(ed25519.PublicKey)
	if !ok || !edPub.Equal(pub) {
		t.Errorf("PublicKey = %v, want %v", got, pub)
	}
}

func TestNewCoseKeyRejectsUnsupportedType(t *testing.T) {
	if _, err := NewCoseKey("not-a-key"); err == nil {
		t.Errorf("NewCoseKey accepted an unsupported key type")
	}
}

func TestCoseKeyPublicKeyRejectsUnsupportedKty(t *testing.T) {
	if _, err := (CoseKey{Kty: 99}).PublicKey(); err == nil {
		t.Errorf("PublicKey accepted an unsupported kty")
	}
}

func TestCoseKeyPublicKeyRejectsBadCoordinateLength(t *testing.T) {
	k := CoseKey{Kty: 2, Crv: 1, X: []byte{1, 2, 3}, Y: []byte{4, 5, 6}}
	if _, err := k.PublicKey(); err == nil {
		t.Errorf("PublicKey accepted EC2 coordinates of the wrong length")
	}
}
