package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// blankIDKeys is a goKeyStore whose CreateKey returns no key ID, though
// its PublicKey answers for that empty ID.
type blankIDKeys struct{ *goKeyStore }

func (s blankIDKeys) CreateKey(purpose string) (string, error) {
	id, err := s.goKeyStore.CreateKey(purpose)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[""] = s.keys[id]
	return "", nil
}

// shortSecret is a KeyAgreement agreeing a secret a byte short of
// P-256's.
type shortSecret struct{}

func (shortSecret) Agree(string, []byte) ([]byte, error) { return make([]byte, 31), nil }

// A platform key itself checks what the app's KeyStore and
// KeyAgreement hand back, so a store getting it wrong fails in the
// wallet as platform, not at an issuer or verifier: a key with no ID, a
// signature by another key, a secret of the wrong length. It signs
// SHA-256 digests only, whatever their length.
func TestPlatformKey_ChecksTheStore(t *testing.T) {
	ctx := context.Background()
	digest := sha256.Sum256([]byte("platform key check"))

	if _, err := (keyStore{ks: blankIDKeys{newGoKeyStore()}}).NewKey(ctx, walletflow.KeyPurposeHolder); code(err) != CodePlatform {
		t.Errorf("a key with no ID: %v, want platform", err)
	}

	wrong := newGoKeyStore()
	key, err := (keyStore{ks: wrong}).NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
		t.Fatalf("the right key: %v", err)
	}
	wrong.wrongKey = true
	if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA256); code(err) != CodePlatform {
		t.Errorf("a signature by another key: %v, want platform", err)
	}
	wrong.wrongKey = false
	if _, err := key.Sign(rand.Reader, digest[:], crypto.SHA512_256); err == nil {
		t.Error("signed a SHA-512/256 digest, SHA-256's length")
	}

	ka := &agreement{}
	var short KeyAgreement = shortSecret{}
	ka.ka.Store(&short)
	agreer, err := (keyStore{ks: newGoKeyStore(), ka: ka}).NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agreer.(proximity.KeyAgreer).Agree(&peer.PublicKey); code(err) != CodePlatform {
		t.Errorf("a 31-byte secret: %v, want platform", err)
	}
}
