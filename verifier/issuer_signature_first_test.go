package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// withBadIssuerSignature is compact, an SD-JWT VC presentation, with
// its Issuer-signed JWT's signature changed.
func withBadIssuerSignature(t *testing.T, compact string) string {
	t.Helper()
	issuerJWT, rest, _ := strings.Cut(compact, "~")
	dot := strings.LastIndexByte(issuerJWT, '.')
	sig := []byte(issuerJWT[dot+1:])
	i := len(sig) / 2
	if sig[i] == 'A' {
		sig[i] = 'B'
	} else {
		sig[i] = 'A'
	}
	return issuerJWT[:dot+1] + string(sig) + "~" + rest
}

// An SD-JWT VC whose issuer signature doesn't verify with the key of
// the x5c leaf it presents is refused as invalid before its chain is
// verified, even when that chain is genuine: a holder of public chains
// can't have each cost a chain check. One the leaf's key signed has its
// chain verified.
func TestVerifyResponse_SDJWTIssuerSignatureBeforeChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	leaf, leafKey := testcert.Leaf(t, "issuer", ca, caKey)
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: multipleQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	genuine := keyBoundPresentation(t, testVCT, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, leafKey, v.ClientID(), built.Nonce)
	var checks atomic.Int32
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&checks}}
	verify := func(presentation string) error {
		_, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
			Query: multipleQuery(t), Response: verifier.ParsedResponse{VPToken: map[string][]string{"pid": {presentation}}},
			ExpectedNonce: built.Nonce, MaxKeyBindingAge: time.Hour, IssuerKeys: resolver,
		})
		return err
	}

	err = verify(withBadIssuerSignature(t, genuine))
	var vErr *verifier.Error
	if !errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonInvalidCredential {
		t.Errorf("a genuine chain under a bad signature: %v, want invalid_credential", err)
	}
	if n := checks.Load(); n != 0 {
		t.Errorf("its chain was verified (%d revocation checks), want none", n)
	}
	if err := verify(genuine); err != nil {
		t.Errorf("the genuine presentation: %v", err)
	}
	if n := checks.Load(); n != 1 {
		t.Errorf("the genuine presentation's chain: %d revocation checks, want 1", n)
	}
}

// An mdoc whose IssuerAuth doesn't verify with the key of the x5chain
// leaf it presents is refused as invalid before its chain is verified,
// even when that chain is genuine. One the leaf's key signed has its
// chain verified.
func TestVerifyResponse_MdocIssuerSignatureBeforeChain(t *testing.T) {
	ca, caKey := testcert.CA(t, "document signer root")
	leaf, leafKey := testcert.Leaf(t, "document signer", ca, caKey)
	mf := newMdocVerifyFixture(t)
	protected, unprotected, payload, err := cose.DecodeUnverified(mf.f.IssuerSigned.IssuerAuth)
	if err != nil {
		t.Fatal(err)
	}
	unprotected.X5Chain = [][]byte{leaf.Raw}
	var checks atomic.Int32
	resolver := verifier.X5ChainIssuerKeyResolver{Roots: rootsOf(ca), LeafPolicy: verifier.AnyIssuerLeaf, Revocation: countingRevocation{&checks}}
	for _, c := range []struct {
		name      string
		signer    *ecdsa.PrivateKey
		wantValid bool
	}{
		{"signed by another key", mf.f.IssuerKey, false},
		{"signed by the leaf's key", leafKey, true},
	} {
		checks.Store(0)
		f := mf
		f.f.IssuerSigned.IssuerAuth, err = cose.Sign(cose.ES256, c.signer, protected, unprotected, payload, []byte{})
		if err != nil {
			t.Fatal(err)
		}
		_, err := f.verifyWith(t, f.nonce, func(r *verifier.VerifyResponseRequest) { r.MdocIssuerKeys = resolver })
		var vErr *verifier.Error
		switch {
		case c.wantValid && checks.Load() != 1:
			t.Errorf("%s: %d revocation checks, want its chain verified once (%v)", c.name, checks.Load(), err)
		case !c.wantValid && checks.Load() != 0:
			t.Errorf("%s: its chain was verified (%d revocation checks), want none", c.name, checks.Load())
		case !c.wantValid && (!errors.As(err, &vErr) || vErr.Reason() != verifier.ReasonInvalidCredential):
			t.Errorf("%s: %v, want invalid_credential", c.name, err)
		}
	}
}
