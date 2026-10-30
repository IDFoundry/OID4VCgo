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
		PreAuthorizedCode: "code-2", Verified: anonymousTokenRequest(),
	}); err == nil {
		t.Error("a request without Verified was accepted under VerifiedPreAuthorizedCode")
	}
}

// TestExchangePreAuthorizedCode_AnonymousRefusesAClient: under
// AnonymousPreAuthorizedCode a Verified request naming a client is
// refused, without spending the code — the grant authenticates none, so
// the embedder took a request it doesn't expect — and one without a
// DPoP key is refused too. The anonymous token is bound to the verified
// key, names no client, and the response carries the Authorization
// Server's next DPoP nonce.
func TestExchangePreAuthorizedCode_AnonymousRefusesAClient(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	for name, v := range map[string]*issuer.VerifiedTokenRequest{
		"a client":    {ClientID: "wallet-1", DPoPThumbprint: "jkt-1"},
		"no DPoP key": {},
		"no Verified": nil,
	} {
		if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: "code-1", Verified: v,
		}); err == nil {
			t.Fatalf("%s: accepted under AnonymousPreAuthorizedCode", name)
		}
	}
	result, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: &issuer.VerifiedTokenRequest{DPoPThumbprint: "jkt-1", NextDPoPNonce: "n-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p := f.tokens.lastParams; p.ClientID != "" || p.Thumbprint != "jkt-1" {
		t.Errorf("AccessTokenParams client %q, thumbprint %q; want none and the verified key", p.ClientID, p.Thumbprint)
	}
	if result.NextDPoPNonce != "n-1" {
		t.Errorf("NextDPoPNonce = %q, want the Authorization Server's", result.NextDPoPNonce)
	}
}

// TestRedeemPreAuthorizedCode: for an Authorization Server that issues
// the token itself, the code is redeemed once — tx_code, expiry and
// authorization_details as ExchangePreAuthorizedCode — with no token
// issued here, and no AccessTokens needed.
func TestRedeemPreAuthorizedCode(t *testing.T) {
	f := newPreAuthorizedCodeFixtureWith(t, func(cfg *issuer.Config, deps *issuer.Dependencies) {
		cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
		deps.AccessTokens = nil
	})
	ctx := context.Background()
	verified := &issuer.VerifiedTokenRequest{ClientID: "wallet-1", DPoPThumbprint: "jkt-1"}
	f.issueWithTxCode(t, "code-1", "1234", issuer.PreAuthorizedCodeRecord{
		Subject: "holder-1", Scopes: []string{"identity_credential"}, CredentialConfigurationIDs: []string{"IdentityCredential"},
		ExpiresAt: f.now.Add(time.Minute),
	})

	if _, err := f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", TxCode: "0000", Verified: verified}); err == nil {
		t.Fatal("a wrong tx_code was accepted")
	}
	got, err := f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", TxCode: "1234", Verified: verified})
	if err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	if got.ClientID != "wallet-1" || got.Subject != "holder-1" || len(got.Scope) != 1 || got.Scope[0] != "identity_credential" {
		t.Errorf("redeemed %+v", got)
	}
	if len(got.AuthorizationDetails) != 1 || got.AuthorizationDetails[0].CredentialConfigurationID != "IdentityCredential" ||
		len(got.AuthorizationDetails[0].CredentialIdentifiers) != 1 {
		t.Errorf("AuthorizationDetails = %+v", got.AuthorizationDetails)
	}
	if f.tokens.lastParams.ClientID != "" {
		t.Error("a token was issued")
	}
	if _, err := f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-1", TxCode: "1234", Verified: verified}); err == nil {
		t.Error("the code was redeemed twice")
	}

	// Without AccessTokens, ExchangePreAuthorizedCode has no way to issue
	// a token: it fails before spending a code.
	f.issue(t, "code-2", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	if _, err := f.iss.ExchangePreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-2", Verified: verified}); err == nil {
		t.Error("ExchangePreAuthorizedCode succeeded without AccessTokens")
	}
	if _, err := f.iss.RedeemPreAuthorizedCode(ctx, issuer.ExchangePreAuthorizedCodeRequest{PreAuthorizedCode: "code-2", Verified: verified}); err != nil {
		t.Errorf("the code was spent by the failed exchange: %v", err)
	}
}

// TestRedeemPreAuthorizedCode_NeedsVerified: an issuer that verifies
// the DPoP proof itself (AnonymousPreAuthorizedCode) issues the token
// too, so it doesn't redeem without issuing.
func TestRedeemPreAuthorizedCode_NeedsVerified(t *testing.T) {
	f := newPreAuthorizedCodeFixture(t)
	f.issue(t, "code-1", issuer.PreAuthorizedCodeRecord{Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)})
	if _, err := f.iss.RedeemPreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
	}); err == nil {
		t.Fatal("RedeemPreAuthorizedCode worked under AnonymousPreAuthorizedCode")
	}
	if _, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
		PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(),
	}); err != nil {
		t.Errorf("the refused redemption spent the code: %v", err)
	}
}
