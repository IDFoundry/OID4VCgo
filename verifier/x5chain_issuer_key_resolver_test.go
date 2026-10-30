package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

func x5chainOf(certs ...*x509.Certificate) [][]byte {
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return chain
}

func TestX5ChainIssuerKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, leafKey := verifiertest.ContractDocumentSignerLeaf(t, "test-leaf", ca, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}

	pub, alg, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chainOf(leaf), "org.iso.18013.5.1.mDL")
	if err != nil {
		t.Fatalf("ResolveMdocIssuerKey: %v", err)
	}
	if alg != cose.ES256 {
		t.Errorf("alg = %v, want cose.ES256", alg)
	}
	gotPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&leafKey.PublicKey) {
		t.Errorf("resolved public key does not match the leaf's own key")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsEmptyChain(t *testing.T) {
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), nil, "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted an empty x5chain")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsSelfSignedLeafEvenIfTrusted(t *testing.T) {
	leaf, _ := verifiertest.ContractSelfSignedLeaf(t, "self-signed-leaf")

	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}

	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chainOf(leaf), "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a self-signed leaf")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, _ := verifiertest.ContractDocumentSignerLeaf(t, "test-leaf", ca, caKey)

	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chainOf(leaf), "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a chain that doesn't lead to a trusted root")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsMalformedEntry(t *testing.T) {
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), [][]byte{[]byte("not a certificate")}, "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a malformed x5chain entry")
	}
}

// RootsByDocType holds each document type to its own anchors: an
// issuer trusted for PIDs can't sign an mDL, and a type it doesn't
// name falls back to Roots, or is refused without Roots.
func TestX5ChainIssuerKeyResolver_RootsByDocType(t *testing.T) {
	const mdl, pid, other = "org.iso.18013.5.1.mDL", "eu.europa.ec.eudi.pid.1", "org.example.other"
	mdlCA, mdlCAKey := verifiertest.ContractCA(t, "mDL CA")
	pidCA, pidCAKey := verifiertest.ContractCA(t, "PID CA")
	mdlLeaf, _ := verifiertest.ContractDocumentSignerLeaf(t, "mDL signer", mdlCA, mdlCAKey)
	pidLeaf, _ := verifiertest.ContractDocumentSignerLeaf(t, "PID signer", pidCA, pidCAKey)
	pool := func(c *x509.Certificate) *x509.CertPool {
		p := x509.NewCertPool()
		p.AddCert(c)
		return p
	}
	ctx := context.Background()
	byType := verifier.X5ChainIssuerKeyResolver{Revocation: certrevocation.NoCheck{}, RootsByDocType: map[string]*x509.CertPool{mdl: pool(mdlCA), pid: pool(pidCA)}}
	for name, tc := range map[string]struct {
		r       verifier.X5ChainIssuerKeyResolver
		leaf    *x509.Certificate
		docType string
		ok      bool
	}{
		"mDL signer, mDL":          {byType, mdlLeaf, mdl, true},
		"PID signer, PID":          {byType, pidLeaf, pid, true},
		"PID signer, mDL":          {byType, pidLeaf, mdl, false},
		"mDL signer, PID":          {byType, mdlLeaf, pid, false},
		"unnamed type, no Roots":   {byType, mdlLeaf, other, false},
		"unnamed type, Roots":      {verifier.X5ChainIssuerKeyResolver{Roots: pool(pidCA), RootsByDocType: byType.RootsByDocType, Revocation: certrevocation.NoCheck{}}, pidLeaf, other, true},
		"named type ignores Roots": {verifier.X5ChainIssuerKeyResolver{Roots: pool(pidCA), RootsByDocType: byType.RootsByDocType, Revocation: certrevocation.NoCheck{}}, pidLeaf, mdl, false},
		"neither":                  {verifier.X5ChainIssuerKeyResolver{Revocation: certrevocation.NoCheck{}}, mdlLeaf, mdl, false},
	} {
		_, _, err := tc.r.ResolveMdocIssuerKey(ctx, x5chainOf(tc.leaf), tc.docType)
		_, chainsErr := tc.r.ResolveMdocIssuerChains(ctx, x5chainOf(tc.leaf), tc.docType)
		if (err == nil) != tc.ok || (chainsErr == nil) != tc.ok {
			t.Errorf("%s: key %v, chains %v; want ok=%v", name, err, chainsErr, tc.ok)
		}
	}
}
