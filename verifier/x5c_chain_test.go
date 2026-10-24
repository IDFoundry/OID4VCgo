package verifier_test

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// An SD-JWT VC issued under an intermediate CA carries it in x5c
// (IssueOptions.IssuerIntermediates), so a Verifier trusting only the
// root resolves the issuer's key; without it, the path can't be built.
func TestX5CIssuerKeyResolver_ChainThroughIntermediate(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, leafKey := testcert.Leaf(t, "issuer", mid, midKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	resolver := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	header := func(intermediates []*x509.Certificate) map[string]any {
		credential, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{VCT: "urn:test"},
			sdjwtvc.IssueOptions{IssuerCertificate: leaf, IssuerIntermediates: intermediates})
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		h, _, err := jose.DecodeUnverified(strings.SplitN(credential, "~", 2)[0])
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	withChain := header([]*x509.Certificate{mid})
	if x5c, _ := withChain["x5c"].([]any); len(x5c) != 2 {
		t.Fatalf("x5c has %d entries, want the leaf and the intermediate", len(x5c))
	}
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), withChain, nil); err != nil {
		t.Errorf("with the intermediate in x5c: %v", err)
	}
	if _, _, err := resolver.ResolveIssuerKey(context.Background(), header(nil), nil); err == nil {
		t.Error("resolved the key without the intermediate the path needs")
	}
	if _, _, err := sdjwtvc.Issue(leafKey, jose.ES256, sdjwtvc.Claims{VCT: "urn:test"},
		sdjwtvc.IssueOptions{IssuerCertificate: leaf, IssuerIntermediates: []*x509.Certificate{mid, root}}); err == nil {
		t.Error("issued with the trust anchor in the chain")
	}
}

// The Request Object's x5c carries the client certificate's chain to
// (not including) the anchor; New refuses a chain out of order, and in
// production a self-signed client certificate (HAIP 1.0 §5).
func TestClientCertificateChain(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	mid, midKey := testcert.Intermediate(t, "intermediate", root, rootKey)
	leaf, leafKey := testcert.Leaf(t, "verifier", mid, midKey)
	cfg, deps := validConfig(t)
	cfg.ClientCertificate, cfg.ClientCertificateChain, deps.Signer = leaf, []*x509.Certificate{mid}, leafKey
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	result, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testIdentityQuery(t), State: "state-1"})
	if err != nil {
		t.Fatal(err)
	}
	header, _, err := jose.DecodeUnverified(result.RequestObject)
	if err != nil {
		t.Fatal(err)
	}
	if x5c, _ := header["x5c"].([]any); len(x5c) != 2 {
		t.Errorf("x5c has %d entries, want the client certificate and the intermediate", len(x5c))
	}

	cfg.ClientCertificateChain = []*x509.Certificate{mid, root}
	if _, err := verifier.New(cfg, deps); err == nil {
		t.Error("New accepted a chain with the trust anchor in it")
	}
	selfSigned, selfSignedKey := testcert.SelfSignedLeaf(t, "self-signed verifier")
	prod, prodDeps := validConfig(t)
	prod.Assurance, prod.ClientCertificate, prodDeps.Signer = verifier.AssuranceProduction, selfSigned, selfSignedKey
	if _, err := verifier.New(prod, prodDeps); err == nil || !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("a self-signed client certificate under production: %v, want refused", err)
	}
}
