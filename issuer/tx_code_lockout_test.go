package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// countOnlyCodeStore counts wrong tx_code attempts but never locks a
// code out itself, as a store that left Consume's maxAttempts to its
// caller would.
type countOnlyCodeStore struct{ *fakePreAuthorizedCodeStore }

func (s countOnlyCodeStore) Consume(ctx context.Context, code, wantTxCodeHash string, _ int, accept func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	return s.fakePreAuthorizedCodeStore.Consume(ctx, code, wantTxCodeHash, 0, accept)
}

// After Limits.MaxTxCodeAttempts wrong tx_codes the issuer invalidates
// the code itself, so the right one is refused afterwards even when the
// store doesn't lock it out: a six-digit PIN can't be guessed by
// retrying.
func TestExchangePreAuthorizedCode_InvalidatesAfterMaxTxCodeAttempts(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(_ *issuer.Config, deps *issuer.Dependencies) {
		deps.PreAuthorizedCodes = countOnlyCodeStore{newFakePreAuthorizedCodeStore()}
	})
	f.issueWithTxCode(t, "code-1", "493536", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute),
	})
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		_, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: "code-1", TxCode: "000000", Verified: anonymousTokenRequest(),
		})
		if err == nil {
			t.Fatalf("wrong tx_code %d accepted", i)
		}
		if i == 3 {
			requireIssuerErrorCode(t, err, issuer.ErrorInvalidGrant)
		}
	}
	if _, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", TxCode: "493536", Verified: anonymousTokenRequest(),
	}); err == nil {
		t.Error("the right tx_code was accepted after MaxTxCodeAttempts wrong ones")
	}
}
