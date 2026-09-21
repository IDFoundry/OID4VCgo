package issuer_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func x5cProofHeader(certs ...*x509.Certificate) map[string]any {
	entries := make([]any, len(certs))
	for i, c := range certs {
		entries[i] = base64.StdEncoding.EncodeToString(c.Raw)
	}
	return map[string]any{"x5c": entries}
}

func TestX5CProofBindingKeyResolver_AcceptsCASignedLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	resolver := issuer.X5CProofBindingKeyResolver{Roots: roots}

	pub, alg, err := resolver.ResolveProofBindingKey(context.Background(), x5cProofHeader(leaf))
	if err != nil {
		t.Fatalf("ResolveProofBindingKey: %v", err)
	}
	gotPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || !gotPub.Equal(&leafKey.PublicKey) {
		t.Errorf("resolved public key does not match the leaf's own key")
	}
	if alg != jose.ES256 {
		t.Errorf("alg = %q, want %q", alg, jose.ES256)
	}
}

func TestX5CProofBindingKeyResolver_RejectsMissingX5C(t *testing.T) {
	resolver := issuer.X5CProofBindingKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveProofBindingKey(context.Background(), map[string]any{"kid": "k1"}); err == nil {
		t.Error("ResolveProofBindingKey accepted a header with no x5c")
	}
}

func TestX5CProofBindingKeyResolver_RejectsEmptyX5C(t *testing.T) {
	resolver := issuer.X5CProofBindingKeyResolver{Roots: x509.NewCertPool()}
	if _, _, err := resolver.ResolveProofBindingKey(context.Background(), map[string]any{"x5c": []any{}}); err == nil {
		t.Error("ResolveProofBindingKey accepted an empty x5c array")
	}
}

func TestX5CProofBindingKeyResolver_RejectsSelfSignedLeafEvenIfTrusted(t *testing.T) {
	leaf, _ := testcert.SelfSignedLeaf(t, "self-signed-leaf")
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	resolver := issuer.X5CProofBindingKeyResolver{Roots: roots}

	if _, _, err := resolver.ResolveProofBindingKey(context.Background(), x5cProofHeader(leaf)); err == nil {
		t.Error("ResolveProofBindingKey accepted a self-signed leaf")
	}
}

func TestX5CProofBindingKeyResolver_RejectsUntrustedChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, _ := testcert.Leaf(t, "test-leaf", ca, caKey)
	resolver := issuer.X5CProofBindingKeyResolver{Roots: x509.NewCertPool()}

	if _, _, err := resolver.ResolveProofBindingKey(context.Background(), x5cProofHeader(leaf)); err == nil {
		t.Error("ResolveProofBindingKey accepted a chain that doesn't lead to a trusted root")
	}
}
