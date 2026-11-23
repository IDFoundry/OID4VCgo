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

	"github.com/idfoundry/oid4vcgo/internal/testcert"
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
	// A leaf for key agreement only can't sign (RFC 5280 §4.2.1.3); one
	// without a key usage extension isn't restricted.
	for usage, ok := range map[x509.KeyUsage]bool{x509.KeyUsageKeyAgreement: false, 0: true} {
		c := mustCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(4), Subject: pkix.Name{CommonName: "leaf"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: usage,
		}, root, &leafKey.PublicKey, rootKey)
		if _, err := VerifyLeaf([][]byte{c.Raw}, roots); (err == nil) != ok {
			t.Errorf("key usage %v: %v", usage, err)
		}
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

// A presented chain is a CA-issued leaf, then each intermediate that
// signed the certificate before it, without the trust anchor.
func TestCheckPresentedChain(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, _ := testcert.Leaf(t, "leaf", mid, midKey)
	direct, _ := testcert.Leaf(t, "direct leaf", root, rootKey)
	selfSigned, _ := testcert.SelfSignedLeaf(t, "self-signed")
	for name, tc := range map[string]struct {
		leaf          *x509.Certificate
		intermediates []*x509.Certificate
		ok            bool
	}{
		"leaf and intermediate":     {leaf, []*x509.Certificate{mid}, true},
		"leaf under the root":       {direct, nil, true},
		"self-signed leaf":          {selfSigned, nil, false},
		"anchor included":           {leaf, []*x509.Certificate{mid, root}, false},
		"intermediate out of order": {direct, []*x509.Certificate{mid}, false},
		"no leaf":                   {nil, nil, false},
	} {
		if err := CheckPresentedChain(tc.leaf, tc.intermediates); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestCheckNoAnchor(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, _ := testcert.Leaf(t, "leaf", mid, midKey)
	for name, tc := range map[string]struct {
		chain [][]byte
		ok    bool
	}{
		"leaf alone":            {[][]byte{leaf.Raw}, true},
		"leaf and intermediate": {[][]byte{leaf.Raw, mid.Raw}, true},
		"the anchor included":   {[][]byte{leaf.Raw, mid.Raw, root.Raw}, false},
		"empty":                 {nil, true},
	} {
		if err := CheckNoAnchor(tc.chain); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}

// A "dns:" iss names one of the certificate's dNSName subject
// alternative names compared in ASCII case only: those are IA5Strings
// (RFC 5280 §4.2.1.6), so a Unicode case fold onto one, the Kelvin
// sign's onto "k" or the long s's onto "s", isn't that name.
func TestCheckIssuerName_DNSFoldsASCIIOnly(t *testing.T) {
	leaf := &x509.Certificate{DNSNames: []string{"key.example", "issuer.example"}}
	for iss, ok := range map[string]bool{
		"dns:key.example":         true,
		"dns:KEY.Example":         true,
		"dns://issuer.example":    true,
		"dns:\u212Aey.example":    false,
		"dns:i\u017Fsuer.example": false,
		"dns:another.example":     false,
		"dns:":                    false,
		"https://issuer.example":  false,
	} {
		if err := CheckIssuerName(leaf, iss); (err == nil) != ok {
			t.Errorf("CheckIssuerName(%q) = %v, want ok = %v", iss, err, ok)
		}
	}
}
