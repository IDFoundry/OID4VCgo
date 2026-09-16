package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/verifier"
)

func x5chainOf(certs ...*x509.Certificate) [][]byte {
	chain := make([][]byte, len(certs))
	for i, c := range certs {
		chain[i] = c.Raw
	}
	return chain
}

func TestX5ChainIssuerKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := testCA(t, "test-ca")
	leaf, leafKey := testLeaf(t, "test-leaf", ca, caKey)

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots}

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
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), nil, "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted an empty x5chain")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsSelfSignedLeafEvenIfTrusted(t *testing.T) {
	leaf, _ := testSelfSignedLeaf(t, "self-signed-leaf")

	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: roots}

	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chainOf(leaf), "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a self-signed leaf")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := testCA(t, "test-ca")
	leaf, _ := testLeaf(t, "test-leaf", ca, caKey)

	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), x5chainOf(leaf), "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a chain that doesn't lead to a trusted root")
	}
}

func TestX5ChainIssuerKeyResolver_RejectsMalformedEntry(t *testing.T) {
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveMdocIssuerKey(context.Background(), [][]byte{[]byte("not a certificate")}, "org.iso.18013.5.1.mDL"); err == nil {
		t.Error("ResolveMdocIssuerKey accepted a malformed x5chain entry")
	}
}
