package wallet

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// TestMdocDeviceAlgForKey covers mdocDeviceAlgForKey's own EdDSA and
// unsupported-key-type branches — found unexercised by any existing
// test in a repo-wide coverage review: every test reaching this
// function only ever used an ECDSA key, so the ed25519.PublicKey and
// default branches had never actually run despite this package
// claiming real EdDSA support.
func TestMdocDeviceAlgForKey(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	cases := map[string]struct {
		pub     interface{}
		want    cose.Alg
		wantErr bool
	}{
		"ecdsa P-256":     {pub: &ecdsaKey.PublicKey, want: cose.ES256},
		"ed25519":         {pub: ed25519Pub, want: cose.EdDSA},
		"unsupported rsa": {pub: &rsaKey.PublicKey, wantErr: true},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := mdocDeviceAlgForKey(tc.pub)
			if tc.wantErr {
				if err == nil {
					t.Errorf("mdocDeviceAlgForKey(%T) = nil error, want error", tc.pub)
				}
				return
			}
			if err != nil {
				t.Fatalf("mdocDeviceAlgForKey(%T): %v", tc.pub, err)
			}
			if got != tc.want {
				t.Errorf("mdocDeviceAlgForKey(%T) = %v, want %v", tc.pub, got, tc.want)
			}
		})
	}
}
