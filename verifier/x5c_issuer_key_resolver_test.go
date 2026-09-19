package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

func x5cHeader(certs ...*x509.Certificate) map[string]any {
	entries := make([]any, len(certs))
	for i, c := range certs {
		entries[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return map[string]any{"x5c": entries}
}

func TestX5CIssuerKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, leafKey := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

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
	leaf, _ := verifier.ContractSelfSignedLeaf(t, "self-signed-leaf")

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
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, _ := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

	// Roots doesn't contain the issuing CA at all.
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}

	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil); err == nil {
		t.Error("ResolveIssuerKey accepted a chain that doesn't lead to a trusted root")
	}
}

func TestX5CIssuerKeyResolver_RejectsWrongTrustAnchor(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, _ := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

	otherCA, _ := verifier.ContractCA(t, "other-ca")
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
