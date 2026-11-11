package mobile

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/proximity"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// providerDetail is err's Detail, "" for none (status_reason_test.go's
// detail is mobiletest's only).
func providerDetail(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// A Wallet Provider's refusal marked with its error code, as the Swift
// and Kotlin adapters mark one, is platform with that code as the
// detail, through classify too; a code that isn't a plain token is
// dropped, the refusal still platform.
func TestProviderError_Refused(t *testing.T) {
	got := providerError("wallet attestation", errors.New("[refused:instance_revoked] the Wallet Provider refused /v1/wallet-attestation: HTTP 403 instance_revoked"))
	if code(got) != CodePlatform || providerDetail(got) != "instance_revoked" || !strings.HasPrefix(got.Error(), "[platform:instance_revoked] wallet attestation: the Wallet Provider refused") {
		t.Errorf("a marked refusal: %v", got)
	}
	if c := classify(fmt.Errorf("walletflow: %w", got)); code(c) != CodePlatform || providerDetail(c) != "instance_revoked" {
		t.Errorf("classify = %v, want the provider's code kept", c)
	}
	for _, msg := range []string{"[refused:not a code] x", "[refused:a\"b] x", "[refused:] x", "[refused:unterminated"} {
		if got := providerError("key attestation", errors.New(msg)); code(got) != CodePlatform || providerDetail(got) != "" {
			t.Errorf("%q: %v, want platform without a detail", msg, got)
		}
	}
}

// A KeyStore or KeyAgreement error marked as the holder's cancellation
// is cancelled, not platform, through classify too.
func TestPlatformKey_HolderCancelled(t *testing.T) {
	ctx := context.Background()
	store := newGoKeyStore()
	ka := &agreement{}
	var agree KeyAgreement = &goKeyAgreement{s: store, err: errors.New("[cancelled] the holder dismissed the prompt")}
	ka.ka.Store(&agree)
	key, err := (keyStore{ks: store, ka: ka}).NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	d := sha256.Sum256([]byte("holder cancelled"))
	store.signErr = errors.New("[cancelled] the holder dismissed Face ID")
	_, err = key.Sign(rand.Reader, d[:], crypto.SHA256)
	if code(err) != CodeCancelled {
		t.Errorf("sign: %v, want cancelled", err)
	}
	if c := classify(fmt.Errorf("walletflow: %w", err)); code(c) != CodeCancelled {
		t.Errorf("classify = %v, want cancelled", c)
	}
	store.signErr = errors.New("keystore busy")
	if _, err := key.Sign(rand.Reader, d[:], crypto.SHA256); code(err) != CodePlatform {
		t.Errorf("an unmarked failure: %v, want platform", err)
	}
	peer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.(proximity.KeyAgreer).Agree(&peer.PublicKey); code(err) != CodeCancelled {
		t.Errorf("agree: %v, want cancelled", err)
	}
}
