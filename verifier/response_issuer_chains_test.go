package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// issuerAuthUnder is f's IssuerAuth signed again by key, presenting
// x5chain.
func issuerAuthUnder(t *testing.T, f testmdoc.Fixture, key *ecdsa.PrivateKey, x5chain ...*x509.Certificate) []byte {
	t.Helper()
	protected, unprotected, payload, err := cose.DecodeUnverified(f.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	unprotected.X5Chain = nil
	for _, cert := range x5chain {
		unprotected.X5Chain = append(unprotected.X5Chain, cert.Raw)
	}
	signed, err := cose.Sign(cose.ES256, key, protected, unprotected, payload, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

// ResponseIssuerChains checks a document's IssuerAuth with its x5chain
// leaf's key before verifying the chain, and verifies a chain shared by
// a response's documents once; a nil one still checks the signature
// first, but verifies each chain afresh.
func TestResponseIssuerChains_SignatureFirstAndOnce(t *testing.T) {
	ca, caKey := testcert.CA(t, "document signer root")
	leaf, leafKey := testcert.Leaf(t, "document signer", ca, caKey)
	f := testmdoc.Issue(t)
	var checks atomic.Int32
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&checks}}
	genuine := issuerAuthUnder(t, f, leafKey, leaf)
	replayed := issuerAuthUnder(t, f, f.IssuerKey, leaf)
	ctx := context.Background()

	for _, c := range []struct {
		name   string
		chains *verifier.ResponseIssuerChains
		want   int32
	}{
		{"NewResponseIssuerChains", verifier.NewResponseIssuerChains(), 1},
		{"the zero value", new(verifier.ResponseIssuerChains), 1},
		{"nil", nil, 3},
	} {
		checks.Store(0)
		if _, err := c.chains.ResolveMdocIssuer(ctx, resolver, replayed, testmdoc.DocType); err == nil || !strings.Contains(err.Error(), "signature doesn't verify") {
			t.Errorf("%s: a genuine chain under another key's signature: %v", c.name, err)
		}
		if n := checks.Load(); n != 0 {
			t.Errorf("%s: its chain was verified (%d revocation checks), want none", c.name, n)
		}
		for range 3 {
			issuer, err := c.chains.ResolveMdocIssuer(ctx, resolver, genuine, testmdoc.DocType)
			if err != nil || !leaf.PublicKey.(*ecdsa.PublicKey).Equal(issuer.Key) {
				t.Fatalf("%s: the genuine document: %v", c.name, err)
			}
		}
		if n := checks.Load(); n != c.want {
			t.Errorf("%s: a chain shared by three documents verified %d times, want %d", c.name, n, c.want)
		}
	}
}

// ResponseIssuerChains refuses, unverified, each further distinct chain
// once MaxFailedIssuerChainsPerResponse of the response's haven't
// verified, as VerifyResponse does.
func TestResponseIssuerChains_FailedChainCap(t *testing.T) {
	ca, _ := testcert.CA(t, "document signer root")
	other, otherKey := testcert.CA(t, "untrusted root")
	f := testmdoc.Issue(t)
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{new(atomic.Int32)}}
	chains := verifier.NewResponseIssuerChains()
	for i := range verifier.MaxFailedIssuerChainsPerResponse + 1 {
		leaf, leafKey := testcert.Leaf(t, fmt.Sprintf("document signer %d", i), other, otherKey)
		_, err := chains.ResolveMdocIssuer(context.Background(), resolver, issuerAuthUnder(t, f, leafKey, leaf), testmdoc.DocType)
		capped := err != nil && strings.Contains(err.Error(), "failed to verify")
		switch {
		case err == nil:
			t.Fatalf("chain %d, no root anchors it: accepted", i)
		case i < verifier.MaxFailedIssuerChainsPerResponse && capped:
			t.Errorf("chain %d refused by the cap: %v", i, err)
		case i == verifier.MaxFailedIssuerChainsPerResponse && !capped:
			t.Errorf("chain %d: %v, want it refused by the cap", i, err)
		}
	}
}
