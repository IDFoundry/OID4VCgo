package dcql_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 5280 key identifier
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

func TestAKITrustedAuthoritiesChecker_AcceptsMatchingAKI(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{aki}}}
	err := dcql.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err != nil {
		t.Fatalf("CheckTrustedAuthorities: %v", err)
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsNonMatchingAKI(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"not-the-right-aki"}}}
	err := dcql.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsNoAKIEntry(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityETSITL, Values: []string{"something"}}}
	err := dcql.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (no aki entry present)")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsEmptyChain(t *testing.T) {
	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}}}
	err := dcql.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, nil)
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (no issuer chain)")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsLeafWithNoAKI(t *testing.T) {
	// A non-CA self-signed leaf gets no SubjectKeyId (Go's own
	// CreateCertificate only generates one for a CA template), and so
	// no AuthorityKeyId either — a real-world equivalent of a
	// certificate whose issuer genuinely never set the extension.
	leaf, _ := testcert.SelfSignedLeaf(t, "test-self-signed")

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}}}
	err := dcql.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (leaf has no AKI extension)")
	}
}

// verifiedAKI is an "aki" trusted_authorities entry naming ca.
func verifiedAKI(ca *x509.Certificate) []dcql.TrustedAuthoritiesQuery {
	return []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{base64.RawURLEncoding.EncodeToString(ca.SubjectKeyId)}}}
}

func pool(cas ...*x509.Certificate) *x509.CertPool {
	p := x509.NewCertPool()
	for _, ca := range cas {
		p.AddCert(ca)
	}
	return p
}

// issue signs a certificate for pub under issuer/issuerKey. authorityKeyID,
// when set, replaces the Authority Key Identifier the leaf would get from
// issuer — as a CA forging another authority's identifier would.
func issue(t *testing.T, tmpl *x509.Certificate, pub *ecdsa.PublicKey, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, authorityKeyID []byte) *x509.Certificate {
	t.Helper()
	parent := *issuer
	if authorityKeyID != nil {
		// crypto/x509 copies the leaf's AKI from the parent's SKI.
		parent.SubjectKeyId = authorityKeyID
	}
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, &parent, pub, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

func TestAKITrustedAuthoritiesChecker_Roots_AcceptsIssuingCA(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)
	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(ca)}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), [][]byte{leaf.Raw}); err != nil {
		t.Fatalf("CheckTrustedAuthorities: %v", err)
	}
}

// TestAKITrustedAuthoritiesChecker_Roots_MatchesAnyCAOnThePath: the
// root named by an intermediate's AKI matches too (OID4VP §6.1.1: "a
// certificate in the certificate chain"), as does the intermediate.
func TestAKITrustedAuthoritiesChecker_Roots_MatchesAnyCAOnThePath(t *testing.T) {
	root, rootKey := testcert.CA(t, "test-root")
	intermediateKey := newKey(t)
	intermediate := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "test-intermediate"},
		// No SubjectKeyId: crypto/x509 derives it from the key (RFC 5280
		// §4.2.1.2 method 1), as CAs normally do.
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, &intermediateKey.PublicKey, root, rootKey, nil)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "test-leaf"}},
		&newKey(t).PublicKey, intermediate, intermediateKey, nil)

	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(root)}
	chain := [][]byte{leaf.Raw, intermediate.Raw}
	for name, ca := range map[string]*x509.Certificate{"root": root, "intermediate": intermediate} {
		if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), chain); err != nil {
			t.Errorf("%s: CheckTrustedAuthorities: %v", name, err)
		}
	}
}

// TestAKITrustedAuthoritiesChecker_Roots_RejectsForgedAKI: a CA trusted
// by the verifier issues a certificate whose Authority Key Identifier
// names a different authority. The chain verifies (through the real
// issuer), but only the real issuer's identifier may match.
func TestAKITrustedAuthoritiesChecker_Roots_RejectsForgedAKI(t *testing.T) {
	other, otherKey := testcert.CA(t, "other-trusted-ca")
	wanted, _ := testcert.CA(t, "wanted-authority")
	forged := issue(t, &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "forged-leaf"}},
		&newKey(t).PublicKey, other, otherKey, wanted.SubjectKeyId)
	if !bytes.Equal(forged.AuthorityKeyId, wanted.SubjectKeyId) {
		t.Fatal("test setup: the forged leaf doesn't carry the wanted authority's key identifier")
	}
	authorities := verifiedAKI(wanted)

	// The leaf's own claim is enough to fool the Roots-less check...
	if err := (dcql.AKITrustedAuthoritiesChecker{}).CheckTrustedAuthorities(context.Background(), authorities, [][]byte{forged.Raw}); err != nil {
		t.Fatalf("test setup: the Roots-less check didn't take the forged AKI (%v)", err)
	}
	// ...but not the verified one.
	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(other, wanted)}
	if err := checker.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{forged.Raw}); err == nil {
		t.Error("CheckTrustedAuthorities accepted a certificate that only claims to be issued by the wanted authority")
	}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(other), [][]byte{forged.Raw}); err != nil {
		t.Errorf("the real issuing CA didn't match: %v", err)
	}
}

func TestAKITrustedAuthoritiesChecker_Roots_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)
	unrelated, _ := testcert.CA(t, "unrelated-ca")
	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(unrelated)}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), [][]byte{leaf.Raw}); err == nil {
		t.Error("CheckTrustedAuthorities accepted a chain that doesn't verify against Roots")
	}
}

// TestAKITrustedAuthoritiesChecker_Roots_RejectsSpoofedIntermediateSKI:
// another trusted CA issues an intermediate declaring the wanted
// authority's Subject Key Identifier. The chain verifies through the
// other CA, but an intermediate matches only by an identifier derived
// from its own key, so the declared one doesn't count.
func TestAKITrustedAuthoritiesChecker_Roots_RejectsSpoofedIntermediateSKI(t *testing.T) {
	wanted, _ := testcert.CA(t, "wanted-authority")
	other, otherKey := testcert.CA(t, "other-trusted-ca")
	spoofKey := newKey(t)
	spoof := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(20), Subject: pkix.Name{CommonName: "other's sub-CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: wanted.SubjectKeyId,
	}, &spoofKey.PublicKey, other, otherKey, nil)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(21), Subject: pkix.Name{CommonName: "other's issuer"}},
		&newKey(t).PublicKey, spoof, spoofKey, nil)

	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(wanted, other)}
	chain := [][]byte{leaf.Raw, spoof.Raw}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(wanted), chain); err == nil {
		t.Error("an intermediate declaring the wanted authority's identifier was accepted as it")
	}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(other), chain); err != nil {
		t.Errorf("the chain's real root didn't match: %v", err)
	}
}

// TestAKITrustedAuthoritiesChecker_Roots_IntermediateDeclaredSKI: an
// intermediate whose declared identifier isn't derived from its key
// matches by the derived one, not the declared one.
func TestAKITrustedAuthoritiesChecker_Roots_IntermediateDeclaredSKI(t *testing.T) {
	root, rootKey := testcert.CA(t, "test-root")
	intermediateKey := newKey(t)
	intermediate := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(30), Subject: pkix.Name{CommonName: "test-intermediate"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: []byte{9, 9, 9, 9},
	}, &intermediateKey.PublicKey, root, rootKey, nil)
	leaf := issue(t, &x509.Certificate{SerialNumber: big.NewInt(31), Subject: pkix.Name{CommonName: "test-leaf"}},
		&newKey(t).PublicKey, intermediate, intermediateKey, nil)
	checker := dcql.AKITrustedAuthoritiesChecker{Roots: pool(root)}
	chain := [][]byte{leaf.Raw, intermediate.Raw}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(intermediate), chain); err == nil {
		t.Error("an intermediate's declared, non-derived identifier matched")
	}
	sum := sha1.Sum(intermediateKeyBits(t, intermediate))
	derived := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{base64.RawURLEncoding.EncodeToString(sum[:])}}}
	if err := checker.CheckTrustedAuthorities(context.Background(), derived, chain); err != nil {
		t.Errorf("the intermediate's key-derived identifier didn't match: %v", err)
	}
}

func intermediateKeyBits(t *testing.T, cert *x509.Certificate) []byte {
	t.Helper()
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		t.Fatal(err)
	}
	return spki.PublicKey.Bytes
}
