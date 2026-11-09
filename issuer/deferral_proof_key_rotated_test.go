package issuer_test

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// switchingProofKeys resolves as next does until *other is set, then
// resolves every header to *other: a kid whose DID Document, say, now
// names another key.
type switchingProofKeys struct {
	next  issuer.ProofBindingKeyResolver
	other *crypto.PublicKey
}

func (r switchingProofKeys) ResolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	pub, alg, err := r.next.ResolveProofBindingKey(ctx, header)
	if *r.other != nil {
		return *r.other, alg, err
	}
	return pub, alg, err
}

// A deferred transaction whose proof's header now resolves to another
// key than when it was deferred is denied: the credential would bind a
// key the header no longer vouches for.
func TestDeferral_DeniesProofKeyNowResolvingElsewhere(t *testing.T) {
	a := newAttesterCRLs(t)
	var other crypto.PublicKey
	f := newDeferralFixture(t, proofKeysUnder(a), func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.ProofBindingKeys = switchingProofKeys{next: deps.ProofBindingKeys, other: &other}
	})
	ctx := context.Background()
	txID := deferX5CProof(t, f, a)

	other = testP256Key(t).Public()
	err := f.iss.IssueDeferredCredential(ctx, txID, issuer.DeferredIssuance{SDJWTClaims: testSDJWTClaims()})
	if !errors.Is(err, issuer.ErrDeferredProofKey) || !strings.Contains(err.Error(), "another key") {
		t.Fatalf("IssueDeferredCredential = %v, want ErrDeferredProofKey: resolves to another key", err)
	}
	_, pollErr := f.iss.RequestDeferredCredential(ctx, deferralAuth, issuer.DeferredCredentialRequest{TransactionID: txID})
	assertIssuerError(t, pollErr, issuer.ErrorCredentialRequestDenied)
}
