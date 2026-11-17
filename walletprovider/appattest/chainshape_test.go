package appattest

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// TestVerifyAttestationChainShape: x5c is exactly Apple's two
// certificates, each with an ECDSA P-256 or P-384 key, and a
// certificate with any other key is refused as malformed before a
// signature is checked. An RSA intermediate with a huge exponent,
// though a trusted root issued it, never reaches crypto/x509's path
// building, which would refuse it ErrUntrustedRoot only after the
// modular exponentiation whose cost the sender chose.
func TestVerifyAttestationChainShape(t *testing.T) {
	f := newFakeApple(t)
	hash := hashOf("client data")
	withX5C := func(edit func(x5c [][]byte) [][]byte) []byte {
		o, _ := f.attest(t, attSpec{clientDataHash: hash})
		var obj attestationObject
		if err := cbor.Unmarshal(o, &obj); err != nil {
			t.Fatal(err)
		}
		obj.AttStmt.X5C = edit(obj.AttStmt.X5C)
		return mustCBOR(t, obj)
	}
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 2048))
	if err != nil {
		t.Fatal(err)
	}
	n.SetBit(n, 2047, 1).SetBit(n, 0, 1)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: f.inter.Subject, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	rsaInter, err := x509.CreateCertificate(rand.Reader, tmpl, f.root, &rsa.PublicKey{N: n, E: 1<<31 - 1}, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	p521 := newKey(t, elliptic.P521())
	p521Inter, err := x509.CreateCertificate(rand.Reader, tmpl, f.root, &p521.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	for name, obj := range map[string][]byte{
		"RSA intermediate":    withX5C(func(x5c [][]byte) [][]byte { return [][]byte{x5c[0], rsaInter} }),
		"P-521 intermediate":  withX5C(func(x5c [][]byte) [][]byte { return [][]byte{x5c[0], p521Inter} }),
		"RSA credential cert": withX5C(func(x5c [][]byte) [][]byte { return [][]byte{rsaInter, x5c[1]} }),
		"three certificates":  withX5C(func(x5c [][]byte) [][]byte { return append(x5c, f.root.Raw) }),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.verifier().VerifyAttestation(obj, hash)
			if !errors.Is(err, ErrMalformed) || errors.Is(err, ErrUntrustedRoot) {
				t.Fatalf("got %v, want ErrMalformed before the chain is built", err)
			}
		})
	}
}
