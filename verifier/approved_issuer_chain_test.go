package verifier_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

var (
	issuerRoleEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	otherRoleEKU  = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 2}
)

// crossCertifiedIssuer is an issuer whose CA's key is certified twice:
// without restriction under open, and under restricting only for
// another role. An EKUInPath policy passes on the path through open,
// and refuses the one through restricting.
type crossCertifiedIssuer struct {
	open, restricting *x509.Certificate
	roots             *x509.CertPool
	// x5chains are the leaf with both CA certificates, in either order.
	x5chains [][][]byte
}

func newCrossCertifiedIssuer(t *testing.T) crossCertifiedIssuer {
	t.Helper()
	restricting, restrictingKey := testcert.CA(t, "restricting root")
	open, openKey := testcert.CA(t, "open root")
	ca, caKey := testcert.Intermediate(t, "shared CA", open, openKey)
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: ca.Subject, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{otherRoleEKU}, SubjectKeyId: ca.SubjectKeyId,
	}, restricting, caKey.Public(), restrictingKey)
	if err != nil {
		t.Fatal(err)
	}
	caRestricted, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := testcert.Issue(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "issuer", Country: []string{"DE"}}, KeyUsage: x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{issuerRoleEKU},
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(restricting)
	roots.AddCert(open)
	return crossCertifiedIssuer{
		open: open, restricting: restricting, roots: roots,
		x5chains: [][][]byte{{leaf.Raw, caRestricted.Raw, ca.Raw}, {leaf.Raw, ca.Raw, caRestricted.Raw}},
	}
}

func (f crossCertifiedIssuer) policy(leaf *x509.Certificate, chains [][]*x509.Certificate) error {
	return certchain.EKUInPath(leaf, chains, issuerRoleEKU)
}

// assertOnlyOpenPaths fails unless every path in chains ends at f.open:
// the paths the policy approved, not the one it refused.
func (f crossCertifiedIssuer) assertOnlyOpenPaths(t *testing.T, chains [][]*x509.Certificate) {
	t.Helper()
	if len(chains) == 0 {
		t.Fatal("no paths")
	}
	for _, chain := range chains {
		if anchor := chain[len(chain)-1]; !anchor.Equal(f.open) {
			t.Errorf("a path to %q, which the leaf policy refuses on its own", anchor.Subject.CommonName)
		}
	}
}

// The issuer chains an SD-JWT VC's resolver gives — the one
// VerifyResponse reports, and IssuerAuthorized, trusted_authorities and
// status binding decide on — are only paths the LeafPolicy approves on
// their own, whatever order the x5c lists the CA's certificates in.
func TestX5CIssuerKeyResolver_ChainsAreThePolicyApprovedPaths(t *testing.T) {
	f := newCrossCertifiedIssuer(t)
	r := verifier.X5CIssuerKeyResolver{Roots: f.roots, LeafPolicy: f.policy, Revocation: certrevocation.NoCheck{}}
	for _, ders := range f.x5chains {
		x5c := make([]any, len(ders))
		for i, der := range ders {
			x5c[i] = base64.StdEncoding.EncodeToString(der)
		}
		header := map[string]any{"x5c": x5c}
		if _, _, err := r.ResolveIssuerKey(context.Background(), header, map[string]any{}); err != nil {
			t.Fatalf("ResolveIssuerKey: %v", err)
		}
		chains, err := r.ResolveIssuerChains(context.Background(), header)
		if err != nil {
			t.Fatalf("ResolveIssuerChains: %v", err)
		}
		f.assertOnlyOpenPaths(t, chains)
	}
}

// The same for an mdoc's document signer.
func TestX5ChainIssuerKeyResolver_ChainsAreThePolicyApprovedPaths(t *testing.T) {
	f := newCrossCertifiedIssuer(t)
	r := verifier.X5ChainIssuerKeyResolver{Roots: f.roots, LeafPolicy: f.policy, Revocation: certrevocation.NoCheck{}}
	for _, x5chain := range f.x5chains {
		chains, err := r.ResolveMdocIssuerChains(context.Background(), x5chain, "org.iso.18013.5.1.mDL")
		if err != nil {
			t.Fatalf("ResolveMdocIssuerChains: %v", err)
		}
		f.assertOnlyOpenPaths(t, chains)
	}
}
