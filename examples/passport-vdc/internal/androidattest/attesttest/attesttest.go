// Package attesttest makes Android Key Attestation chains for tests: a
// root, an intermediate and a leaf certifying a key with the attestation
// extension, as Android Keystore's are, but under a root of the test's
// own (so they're synthesised, not a device's).
package attesttest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
)

// Chain is a synthesised attestation chain.
type Chain struct {
	// DER holds the leaf, the intermediate and the root, in that order.
	DER [][]byte
	// Root is the chain's root, to trust (or not) in a test.
	Root *x509.Certificate
	// IntermediateKey signs the leaf, to sign another one with.
	IntermediateKey *ecdsa.PrivateKey
}

// Options shapes the leaf's key description.
type Options struct {
	// Level is both the attestation and the key's security level.
	Level androidattest.SecurityLevel
	// Challenge is the attestation challenge.
	Challenge []byte
}

// KeyDescription encodes a key description extension value for opts,
// with empty authorization lists.
func KeyDescription(t testing.TB, opts Options) []byte {
	t.Helper()
	empty := asn1.RawValue{FullBytes: []byte{0x30, 0x00}}
	der, err := asn1.Marshal(struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeyMintVersion           int
		KeyMintSecurityLevel     asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		HardwareEnforced         asn1.RawValue
	}{300, asn1.Enumerated(opts.Level), 300, asn1.Enumerated(opts.Level), opts.Challenge, []byte{}, empty, empty})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// New makes a chain attesting key over opts.
func New(t testing.TB, key crypto.PublicKey, opts Options) Chain {
	t.Helper()
	rootKey, root := ca(t, nil, nil, "test attestation root")
	interKey, inter := ca(t, root, rootKey, "test attestation intermediate")
	leaf := Leaf(t, inter, interKey, key, KeyDescription(t, opts))
	return Chain{DER: [][]byte{leaf.Raw, inter.Raw, root.Raw}, Root: root, IntermediateKey: interKey}
}

// Leaf makes a leaf certifying key, signed by parent's key, with ext as
// its attestation extension (none when nil).
func Leaf(t testing.TB, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, key crypto.PublicKey, ext []byte) *x509.Certificate {
	t.Helper()
	tmpl := template("Android Keystore Key", false)
	if ext != nil {
		tmpl.ExtraExtensions = []pkix.Extension{{Id: androidattest.OID, Value: ext}}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func template(cn string, ca bool) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: ca, BasicConstraintsValid: ca, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
}

// ca makes a CA certificate signed by parentKey, or a self-signed root
// when parent is nil.
func ca(t testing.TB, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, cn string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := template(cn, true)
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, c
}
