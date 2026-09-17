package verifier_test

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

	"github.com/idfoundry/oid4vcgo/verifier"
)

// testCA builds a fresh EC P-256 self-signed CA certificate/key —
// unlike internal/testcert.SelfSigned (no IsCA/BasicConstraints,
// meant for a single leaf a caller trusts directly), this one is
// usable as an intermediate/root in x509.Certificate.Verify's own
// chain building.
func testCA(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
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

// testLeaf issues a leaf certificate under ca/caKey for a fresh EC
// P-256 key, returning the leaf certificate and its own private key.
func testLeaf(t *testing.T, commonName string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
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
	return cert, key
}

// testSelfSignedLeaf builds a fresh EC P-256 self-signed leaf
// certificate (its own issuer, no CA extension) and its own private
// key.
func testSelfSignedLeaf(t *testing.T, commonName string) (*x509.Certificate, *ecdsa.PrivateKey) {
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
	return cert, key
}

func x5cHeader(certs ...*x509.Certificate) map[string]any {
	entries := make([]any, len(certs))
	for i, c := range certs {
		entries[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return map[string]any{"x5c": entries}
}

func TestX5CIssuerKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := testCA(t, "test-ca")
	leaf, leafKey := testLeaf(t, "test-leaf", ca, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots}

	pub, alg, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil)
	if err != nil {
		t.Fatalf("ResolveIssuerKey: %v", err)
	}
	if alg != "ES256" {
		t.Errorf("alg = %q, want ES256", alg)
	}
	gotPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&leafKey.PublicKey) {
		t.Errorf("resolved public key does not match the leaf's own key")
	}
}

func TestX5CIssuerKeyResolver_RejectsMissingX5C(t *testing.T) {
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), map[string]any{}, nil); err == nil {
		t.Error("ResolveIssuerKey accepted a header with no x5c")
	}
}

func TestX5CIssuerKeyResolver_RejectsEmptyX5C(t *testing.T) {
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}
	header := map[string]any{"x5c": []any{}}
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), header, nil); err == nil {
		t.Error("ResolveIssuerKey accepted an empty x5c array")
	}
}

func TestX5CIssuerKeyResolver_RejectsSelfSignedLeafEvenIfTrusted(t *testing.T) {
	leaf, _ := testSelfSignedLeaf(t, "self-signed-leaf")

	// The self-signed leaf is itself in Roots — chain-building alone
	// would succeed, but HAIP's own trust model rejects a self-signed
	// leaf outright regardless.
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots}

	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil); err == nil {
		t.Error("ResolveIssuerKey accepted a self-signed leaf")
	}
}

func TestX5CIssuerKeyResolver_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := testCA(t, "test-ca")
	leaf, _ := testLeaf(t, "test-leaf", ca, caKey)

	// Roots doesn't contain the issuing CA at all.
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}

	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil); err == nil {
		t.Error("ResolveIssuerKey accepted a chain that doesn't lead to a trusted root")
	}
}

func TestX5CIssuerKeyResolver_RejectsWrongTrustAnchor(t *testing.T) {
	ca, caKey := testCA(t, "test-ca")
	leaf, _ := testLeaf(t, "test-leaf", ca, caKey)

	otherCA, _ := testCA(t, "other-ca")
	roots := x509.NewCertPool()
	roots.AddCert(otherCA)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots}

	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil); err == nil {
		t.Error("ResolveIssuerKey accepted a leaf chaining to a CA that isn't a trusted root")
	}
}

func TestX5CIssuerKeyResolver_RejectsMalformedX5CEntry(t *testing.T) {
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}
	header := map[string]any{"x5c": []any{"not valid base64!!!"}}
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), header, nil); err == nil {
		t.Error("ResolveIssuerKey accepted a malformed x5c entry")
	}
}
