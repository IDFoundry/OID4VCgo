package issuer_test

import (
	"context"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// A pointer to VerifiedPreAuthorizedCode is the choice itself: a
// redemption with only a DPoP proof, which the Authorization Server
// didn't verify, is refused as with the value. Every check asks for the
// value type, so a pointer used to redeem with no client
// authentication while passing them all.
func TestExchangePreAuthorizedCode_PointerToVerified(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, _ *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = &issuer.VerifiedPreAuthorizedCode{}
	})
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Subject: "alice", ExpiresAt: f.now.Add(1e12)})
	res, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
	})
	if err == nil || res.AccessToken != "" {
		t.Errorf("an unverified redemption under &VerifiedPreAuthorizedCode{}: token issued %v, err %v; want refused", res.AccessToken != "", err)
	}

	var nilVerified *issuer.VerifiedPreAuthorizedCode
	cfg := validConfig(t)
	cfg.PreAuthorizedCodeClientAuthentication = nilVerified
	if _, err := issuer.New(cfg, validDependencies(t)); err == nil {
		t.Error("a nil *VerifiedPreAuthorizedCode was accepted")
	}
}
