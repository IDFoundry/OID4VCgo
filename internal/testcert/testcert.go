// Package testcert builds throwaway self-signed X.509 certificates for
// tests that need a *x509.Certificate (e.g. verifier.Config's own
// ClientCertificate) — never for production use. It's a regular (not
// _test.go) package specifically so more than one package's own test
// files can share it; Go doesn't let a _test.go file's own symbols be
// imported from another package's tests.
package testcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// SelfSigned builds a self-signed leaf certificate for pub, signed by
// signer (ordinarily pub's own corresponding private key), valid from
// an hour ago to 24 hours from now. t is testing.TB, not *testing.T,
// so a FuzzXxx target's own *testing.F can build seed material with
// it too — both implement testing.TB, and *testing.F.Fatalf works the
// same way *testing.T.Fatalf does at fuzz-setup time (before f.Fuzz's
// own callback runs).
func SelfSigned(t testing.TB, commonName string, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatalf("testcert: CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcert: ParseCertificate: %v", err)
	}
	return cert
}

// CA builds a fresh EC P-256 self-signed CA certificate/key — unlike
// SelfSigned (no IsCA/BasicConstraints, meant for a single leaf a
// caller trusts directly), this one is usable as an
// intermediate/root in x509.Certificate.Verify's own chain building.
func CA(t testing.TB, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcert: generate CA key: %v", err)
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
		t.Fatalf("testcert: create CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcert: parse CA certificate: %v", err)
	}
	return cert, key
}

// Leaf issues a leaf certificate under ca/caKey (ordinarily built with
// CA) for a fresh EC P-256 key.
func Leaf(t testing.TB, commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcert: generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("testcert: create leaf certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcert: parse leaf certificate: %v", err)
	}
	return cert, key
}

// SelfSignedLeaf builds a fresh EC P-256 self-signed leaf certificate
// (its own issuer, no CA extension) and its own private key — unlike
// SelfSigned, which signs an already-generated pub with a possibly
// different signer, this generates its own key pair and self-signs it,
// for tests that specifically need "the leaf's own signature was
// produced by the leaf's own key" (e.g. internal/certchain.IsSelfSigned
// contract checks).
func SelfSignedLeaf(t testing.TB, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("testcert: generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("testcert: create self-signed certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("testcert: parse self-signed certificate: %v", err)
	}
	return cert, key
}

// AssertSingleX5CHeader asserts compact's own JWS header — or, for a
// compact SD-JWT VC, its Issuer-signed JWT component before the first
// "~" — carries exactly one "x5c" entry (RFC 7515 §4.1.6), returning
// it: the check both credential/sdjwtvc's own IssuerCertificate tests
// and issuer's own need identically, the returned slice letting a
// caller that wants to inspect the entry itself continue from there.
func AssertSingleX5CHeader(t *testing.T, compact string) []any {
	t.Helper()
	issuerJWT, _, _ := strings.Cut(compact, "~")
	header, _, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatalf("testcert: DecodeUnverified: %v", err)
	}
	x5c, ok := header["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("header[\"x5c\"] = %#v, want a single-entry array", header["x5c"])
	}
	return x5c
}
