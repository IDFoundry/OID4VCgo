package certchain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestVerifyChains_Refuses: a nil root pool is refused rather than read
// as the system's roots, and so is a leaf that's a CA certificate; an
// end-entity leaf under the roots verifies.
func TestVerifyChains_Refuses(t *testing.T) {
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &rootKey.PublicKey, rootKey)
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subCA := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "sub CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, IsCA: true, BasicConstraintsValid: true,
	}, root, &caKey.PublicKey, rootKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, root, &leafKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	if _, err := VerifyLeaf([][]byte{leaf.Raw}, roots); err != nil {
		t.Fatalf("an end-entity leaf: %v", err)
	}
	if _, err := VerifyLeaf([][]byte{leaf.Raw}, nil); err == nil || !strings.Contains(err.Error(), "no trust anchors") {
		t.Errorf("nil roots: %v, want refused", err)
	}
	if _, err := VerifyLeaf([][]byte{subCA.Raw}, roots); err == nil || !strings.Contains(err.Error(), "CA certificate") {
		t.Errorf("a CA certificate as the leaf: %v, want refused", err)
	}
}

// TestVerifyChainsAt: validity is checked at the given time, not the
// current one — a chain valid now is refused once now passes the
// leaf's NotAfter, and a zero time still means the current time.
func TestVerifyChainsAt(t *testing.T) {
	now := time.Now()
	rootKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &rootKey.PublicKey, rootKey)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
	}, root, &leafKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	if _, _, err := VerifyChainsAt([][]byte{leaf.Raw}, roots, time.Time{}); err != nil {
		t.Fatalf("zero time: %v", err)
	}
	if _, _, err := VerifyChainsAt([][]byte{leaf.Raw}, roots, now.Add(30*time.Minute)); err != nil {
		t.Fatalf("inside the validity period: %v", err)
	}
	if _, _, err := VerifyChainsAt([][]byte{leaf.Raw}, roots, now.Add(2*time.Hour)); err == nil {
		t.Error("after the leaf's NotAfter: verified, want refused")
	}
}
