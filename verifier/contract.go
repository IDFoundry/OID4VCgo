package verifier

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"testing"
	"time"
)

// This file is a reusable contract test for one specific, common
// shape of SDJWTVCIssuerKeyResolver/MdocIssuerKeyResolver
// implementation — NOT a generic contract for either bare interface.
// Both interfaces deliberately leave HOW trust is determined up to the
// implementation (a certificate chain checked against a trust anchor
// set, as X5CIssuerKeyResolver/X5ChainIssuerKeyResolver implement; DID
// resolution; VCT metadata lookup; ...) — there is no single property
// every implementation must have the way a NonceStore's atomicity
// (issuer/contract.go) is universal regardless of backend. What the
// two functions below check is specific to the "certificate chain
// verified against a *x509.CertPool" strategy: a caller building their
// own resolver this way (the only strategy this package ships an
// example of) can run one against their own factory to catch the same
// class of mistake a repo-wide security review once found in an early
// version of this package's own resolvers — accepting a self-signed
// leaf, or a chain that doesn't actually validate against the
// configured roots (see X5CIssuerKeyResolver's own doc comment).

// contractCA builds a fresh EC P-256 self-signed CA certificate/key,
// usable as an intermediate/root in x509.Certificate.Verify's own
// chain building.
func contractCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	return cert, key
}

// contractLeaf issues a leaf certificate under ca/caKey for a fresh EC
// P-256 key.
func contractLeaf(t *testing.T, commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return cert
}

// contractSelfSignedLeaf builds a fresh EC P-256 self-signed leaf
// certificate (its own issuer, no CA extension).
func contractSelfSignedLeaf(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create self-signed certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed certificate: %v", err)
	}
	return cert
}

// TestX5CTrustContract exercises factory(roots)'s behavior against the
// properties any x5c-chain-based SDJWTVCIssuerKeyResolver should
// have — see this file's own package-level note for what this does
// and doesn't claim to cover.
func TestX5CTrustContract(t *testing.T, factory func(roots *x509.CertPool) SDJWTVCIssuerKeyResolver) {
	t.Helper()
	testCertChainTrustContract(t, func(roots *x509.CertPool, certs ...*x509.Certificate) error {
		entries := make([]any, len(certs))
		for i, c := range certs {
			entries[i] = base64.StdEncoding.EncodeToString(c.Raw)
		}
		_, _, err := factory(roots).ResolveIssuerKey(context.Background(), map[string]any{"x5c": entries}, nil)
		return err
	})
}

// TestX5ChainTrustContract is TestX5CTrustContract's own twin for a
// x5chain-based MdocIssuerKeyResolver — see this file's own
// package-level note.
func TestX5ChainTrustContract(t *testing.T, factory func(roots *x509.CertPool) MdocIssuerKeyResolver) {
	t.Helper()
	testCertChainTrustContract(t, func(roots *x509.CertPool, certs ...*x509.Certificate) error {
		chain := make([][]byte, len(certs))
		for i, c := range certs {
			chain[i] = c.Raw
		}
		_, _, err := factory(roots).ResolveMdocIssuerKey(context.Background(), chain, "org.iso.18013.5.1.mDL")
		return err
	})
}

// testCertChainTrustContract runs the shared checks
// TestX5CTrustContract and TestX5ChainTrustContract both need against
// resolve, which must present certs (leaf first) to a resolver built
// with roots and report whatever error (if any) it returned —
// hiding the one thing that differs between an x5c (JSON+base64
// header member) and an x5chain (raw DER byte slices) resolver.
func testCertChainTrustContract(t *testing.T, resolve func(roots *x509.CertPool, certs ...*x509.Certificate) error) {
	t.Helper()

	t.Run("AcceptsCASignedLeaf", func(t *testing.T) {
		ca, caKey := contractCA(t, "test-ca")
		leaf := contractLeaf(t, "test-leaf", ca, caKey)
		roots := x509.NewCertPool()
		roots.AddCert(ca)

		if err := resolve(roots, leaf); err != nil {
			t.Errorf("resolve: %v, want a CA-signed leaf to be accepted", err)
		}
	})

	t.Run("RejectsSelfSignedLeafEvenIfTrusted", func(t *testing.T) {
		leaf := contractSelfSignedLeaf(t, "test-leaf")
		roots := x509.NewCertPool()
		roots.AddCert(leaf) // the self-signed leaf is itself a configured root.

		if err := resolve(roots, leaf); err == nil {
			t.Error("resolve = nil error, want a self-signed leaf to be rejected even when it is itself a trust anchor")
		}
	})

	t.Run("RejectsUntrustedChain", func(t *testing.T) {
		ca, caKey := contractCA(t, "test-ca")
		leaf := contractLeaf(t, "test-leaf", ca, caKey)
		untrustedCA, _ := contractCA(t, "untrusted-ca")
		roots := x509.NewCertPool()
		roots.AddCert(untrustedCA) // does not chain to the leaf's own issuer.

		if err := resolve(roots, leaf); err == nil {
			t.Error("resolve = nil error, want a chain that doesn't validate against roots to be rejected")
		}
	})
}
