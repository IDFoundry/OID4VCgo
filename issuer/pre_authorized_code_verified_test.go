package issuer_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestExchangePreAuthorizedCode_Verified: under VerifiedPreAuthorizedCode
// the Authorization Server's verification of the client and DPoP proof is
// taken as given — no DPoP proof is checked here — and the token is bound
// to that client and key, with the Authorization Server's next nonce.
func TestExchangePreAuthorizedCode_Verified(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
		cfg.Limits.MaxDPoPProofAge = 0 // the Authorization Server's to check
		deps.DPoPReplay = nil
	})
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})

	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: &issuer.VerifiedTokenRequest{ClientID: "wallet-1"},
	}); err == nil {
		t.Fatal("a Verified request without a DPoP thumbprint was accepted")
	}
	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1",
		Verified:          &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1", NextDPoPNonce: "n-1"},
	})
	if err != nil {
		t.Fatalf("ExchangePreAuthorizedCode: %v", err)
	}
	if p := f.tokens.lastParams; p.ClientID != "wallet-1" || p.Thumbprint != "jkt-1" {
		t.Errorf("AccessTokenParams client %q, thumbprint %q; want the verified ones", p.ClientID, p.Thumbprint)
	}
	if result.NextDPoPNonce != "n-1" {
		t.Errorf("NextDPoPNonce = %q, want the Authorization Server's", result.NextDPoPNonce)
	}

	f.issue(t, "code-2", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-2", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	}); err == nil {
		t.Error("a request without Verified was accepted under VerifiedPreAuthorizedCode")
	}
}

// TestExchangePreAuthorizedCode_AnonymousRefusesVerified: Verified means
// nothing without VerifiedPreAuthorizedCode, so it's refused rather than
// trusted, and an anonymous token names no client.
func TestExchangePreAuthorizedCode_AnonymousRefusesVerified(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
		Verified: &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"},
	}); err == nil {
		t.Fatal("Verified was trusted without VerifiedPreAuthorizedCode")
	}
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", DPoPProof: f.validProof(t), TokenEndpoint: testTokenEndpointURL(t),
	}); err != nil {
		t.Fatal(err)
	}
	if f.tokens.lastParams.ClientID != "" {
		t.Errorf("AccessTokenParams.ClientID = %q, want none", f.tokens.lastParams.ClientID)
	}
}
