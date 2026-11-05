package verifier_test

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

// countingRevocation is a certrevocation.Checker counting the chains
// it's asked about, and accepting each.
type countingRevocation struct{ checks *atomic.Int32 }

func (c countingRevocation) CheckRevocation(context.Context, certrevocation.Check) error {
	c.checks.Add(1)
	return nil
}

// An X5CIssuerKeyResolver's x5c header is verified once per SD-JWT VC,
// for both the issuer key and the issuer chain VerifyResponse reports,
// whether the resolver is given as a value or a pointer.
func TestVerifyResponse_X5CVerifiedOnce(t *testing.T) {
	ca, caKey := verifiertest.ContractCA(t, "test-ca")
	leaf, leafKey := verifiertest.ContractLeaf(t, "test-leaf", ca, caKey)
	query := testIdentityQuery(t)
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSDJWTVCPresentationWithIssuerOpts(t, leafKey, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, v.ClientID(), built.Nonce)
	var checks atomic.Int32
	resolver := verifier.X5CIssuerKeyResolver{Roots: rootsOf(ca), Revocation: countingRevocation{&checks}}
	for name, keys := range map[string]verifier.SDJWTVCIssuerKeyResolver{"value": resolver, "pointer": &resolver} {
		t.Run(name, func(t *testing.T) {
			checks.Store(0)
			result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
				Query:            query,
				Response:         verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
				ExpectedNonce:    built.Nonce,
				IssuerKeys:       keys,
				MaxKeyBindingAge: time.Hour,
			})
			cred := testverify.RequireOneCredential(t, result, err, "identity_credential")
			if n := checks.Load(); n != 1 {
				t.Errorf("issuer chain checked for revocation %d times, want 1", n)
			}
			if len(cred.IssuerChain) != 1 || !bytes.Equal(cred.IssuerChain[0], leaf.Raw) {
				t.Errorf("IssuerChain = %d certificates, want the leaf alone (the path less its anchor)", len(cred.IssuerChain))
			}
		})
	}
}
