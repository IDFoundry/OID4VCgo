package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// The pre-authorized code grant's negative vector not already in
// TestExchangePreAuthorizedCode_Rejects: a code redeemed twice. The
// unchanged request is the control. The Token Request's DPoP proof is
// the Authorization Server's to verify (fapigo/server's
// VerifyTokenRequestDPoP, or VerifyTokenRequestBinding with a client),
// so its vectors are fapigo/server's.
func TestPreAuthorizedCodeNegativeVectors(t *testing.T) {
	ctx := context.Background()
	exchange := func(f preAuthorizedCodeFixture) error {
		_, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
		})
		return err
	}
	fresh := func() preAuthorizedCodeFixture {
		f := newPreAuthorizedCodeFixture(t)
		f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
		return f
	}
	if exchange(fresh()) != nil {
		t.Fatal("the control is refused, so no refusal below means anything")
	}
	for _, vec := range []struct {
		id, clause string
		code       issuer.ErrorCode
		setup      func(f preAuthorizedCodeFixture)
	}{
		{"code-redeemed-twice", "RFC 6749 §4.1.2 / OpenID4VCI 1.0 §6.1 (a code is used once)", issuer.ErrorInvalidGrant,
			func(f preAuthorizedCodeFixture) {
				if err := exchange(f); err != nil {
					t.Fatalf("the first exchange: %v", err)
				}
			}},
	} {
		t.Run(vec.id, func(t *testing.T) {
			f := fresh()
			vec.setup(f)
			err := exchange(f)
			if err == nil {
				t.Fatalf("accepted (%s)", vec.clause)
			}
			requireIssuerErrorCode(t, err, vec.code)
		})
	}
}
