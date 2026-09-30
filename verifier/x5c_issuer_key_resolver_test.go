package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

func x5cHeader(certs ...*x509.Certificate) map[string]any {
	entries := make([]any, len(certs))
	for i, c := range certs {
		entries[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return map[string]any{"x5c": entries}
}

func TestX5CIssuerKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, leafKey := verifiertest.ContractLeaf(t, "test-leaf", ca, caKey)

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
	leaf, _ := verifiertest.ContractSelfSignedLeaf(t, "self-signed-leaf")

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
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, _ := verifiertest.ContractLeaf(t, "test-leaf", ca, caKey)

	// Roots doesn't contain the issuing CA at all.
	resolver := verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool()}

	if _, _, err := resolver.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil); err == nil {
		t.Error("ResolveIssuerKey accepted a chain that doesn't lead to a trusted root")
	}
}

func TestX5CIssuerKeyResolver_RejectsWrongTrustAnchor(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, _ := verifiertest.ContractLeaf(t, "test-leaf", ca, caKey)

	otherCA, _ := verifiertest.ContractCA(t, "other-ca")
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

// TestX5CResolvers_LeafPolicy: each x5c/x5chain resolver runs LeafPolicy
// on the verified leaf, with its verified paths, and refuses what it
// refuses.
func TestX5CResolvers_LeafPolicy(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, _ := verifiertest.ContractLeaf(t, "test-leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	var seenLeaf *x509.Certificate
	var seenChains [][]*x509.Certificate
	accept := func(l *x509.Certificate, chains [][]*x509.Certificate) error {
		seenLeaf, seenChains = l, chains
		return nil
	}
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("not an issuer certificate") }

	resolve := map[string]func(policy func(*x509.Certificate, [][]*x509.Certificate) error) error{
		"x5c": func(policy func(*x509.Certificate, [][]*x509.Certificate) error) error {
			_, _, err := verifier.X5CIssuerKeyResolver{Roots: roots, LeafPolicy: policy}.ResolveIssuerKey(context.Background(), x5cHeader(leaf), nil)
			return err
		},
		"x5chain": func(policy func(*x509.Certificate, [][]*x509.Certificate) error) error {
			_, _, err := verifier.X5ChainIssuerKeyResolver{Roots: roots, LeafPolicy: policy}.ResolveMdocIssuerKey(context.Background(), [][]byte{leaf.Raw}, "doc")
			return err
		},
	}
	for name, run := range resolve {
		seenLeaf, seenChains = nil, nil
		if err := run(accept); err != nil {
			t.Errorf("%s: accepting policy: %v", name, err)
		}
		if seenLeaf == nil || !seenLeaf.Equal(leaf) || len(seenChains) == 0 || !seenChains[0][len(seenChains[0])-1].Equal(ca) {
			t.Errorf("%s: policy didn't get the verified leaf and its path to the root", name)
		}
		if err := run(refuse); err == nil {
			t.Errorf("%s: a leaf the policy refused was accepted", name)
		}
	}
}
