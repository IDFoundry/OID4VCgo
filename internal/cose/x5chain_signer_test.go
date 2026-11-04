package cose

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// X5ChainSigner verifies a token's x5chain and returns its leaf and
// the alg the leaf's key signs with; a leaf whose key this package
// can't verify with is refused with an error that says so.
func TestX5ChainSigner(t *testing.T) {
	ca, caKey := testcert.CA(t, "x5chain CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	p256, p256Key := testcert.Leaf(t, "P-256 signer", ca, caKey)
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ed := testcert.LeafFor(t, "Ed25519 signer", edPub, ca, caKey)
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384 := testcert.LeafFor(t, "P-384 signer", &p384Key.PublicKey, ca, caKey)
	p521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521 := testcert.LeafFor(t, "P-521 signer", &p521Key.PublicKey, ca, caKey)
	p224Key, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p224 := testcert.LeafFor(t, "P-224 signer", &p224Key.PublicKey, ca, caKey)

	// X5ChainSigner doesn't check the signature, so any key signs a
	// token carrying a leaf it can't sign with.
	token := func(alg Alg, key crypto.Signer, protected, unprotected *x509.Certificate) []byte {
		var p, u Headers
		if protected != nil {
			p.X5Chain = [][]byte{protected.Raw}
		}
		if unprotected != nil {
			u.X5Chain = [][]byte{unprotected.Raw}
		}
		b, err := SignTagged(alg, key, p, u, []byte("payload"), nil)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	trust := func(protectedOnly bool, roots *x509.CertPool) X5ChainTrust {
		return X5ChainTrust{MaxBytes: 1 << 16, ProtectedOnly: protectedOnly, Roots: roots, Now: time.Now()}
	}
	ctx := context.Background()
	for name, tc := range map[string]struct {
		sign1 []byte
		trust X5ChainTrust
		leaf  *x509.Certificate
		alg   Alg
	}{
		"P-256":       {token(ES256, p256Key, p256, nil), trust(true, roots), p256, ES256},
		"Ed25519":     {token(EdDSA, edKey, ed, nil), trust(true, roots), ed, EdDSA},
		"P-384":       {token(ES384, p384Key, p384, nil), trust(true, roots), p384, ES384},
		"P-521":       {token(ES512, p521Key, p521, nil), trust(true, roots), p521, ES512},
		"unprotected": {token(ES256, p256Key, nil, p256), trust(false, roots), p256, ES256},
	} {
		leaf, alg, err := X5ChainSigner(ctx, tc.sign1, tc.trust)
		if err != nil || leaf != nil && !leaf.Equal(tc.leaf) || alg != tc.alg {
			t.Errorf("%s: %v, %v, %v", name, leaf != nil, alg, err)
		}
	}
	for name, tc := range map[string]struct {
		sign1 []byte
		trust X5ChainTrust
		want  string
	}{
		"P-224":                      {token(ES256, p256Key, p224, nil), trust(true, roots), "token signer: an ECDSA key on P-224, but only P-256 (ES256), P-384 (ES384), P-521 (ES512) and Ed25519 (EdDSA) are supported"},
		"unprotected, ProtectedOnly": {token(ES256, p256Key, nil, p256), trust(true, roots), "token signer"},
		"untrusted":                  {token(ES256, p256Key, p256, nil), trust(true, x509.NewCertPool()), "token signer"},
		"not a COSE_Sign1":           {[]byte{0xa0}, trust(true, roots), "decode token"},
		"over MaxBytes":              {token(ES256, p256Key, p256, nil), X5ChainTrust{MaxBytes: 10, Roots: roots}, "decode token"},
	} {
		_, _, err := X5ChainSigner(ctx, tc.sign1, tc.trust)
		if err == nil || !strings.HasPrefix(err.Error(), tc.want) {
			t.Errorf("%s: %v, want an error starting %q", name, err, tc.want)
		}
	}
}
