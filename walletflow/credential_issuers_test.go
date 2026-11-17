package walletflow_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// With Config.CredentialIssuers set, an offer from another issuer is
// refused by StartIssuance, before the holder is asked for a PIN, so
// the PIN never reaches it (OpenID4VCI 1.0, Transaction Code Phishing).
// A listed issuer's offer is redeemed as usual.
func TestStartIssuance_CredentialIssuers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	walletFor := func(issuers ...string) *walletflow.Wallet {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
			IssuerRoots: f.env.IssuerRoots, CredentialIssuers: issuers,
		}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}

	other := walletFor("https://issuer.other.example")
	if _, err := other.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID)); !errors.Is(err, walletflow.ErrUntrustedIssuer) {
		t.Fatalf("an unlisted issuer's offer: %v, want ErrUntrustedIssuer", err)
	}

	listed := walletFor("https://issuer.other.example", f.env.IssuerURL)
	s, err := listed.StartIssuance(ctx, f.env.PreAuthorizedOffer(t, "493536", walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatalf("a listed issuer's offer: %v", err)
	}
	defer func() { _ = s.Close(ctx) }()
	if err := s.RedeemPreAuthorizedCode(ctx, "493536"); err != nil {
		t.Fatalf("RedeemPreAuthorizedCode: %v", err)
	}
	if _, err := s.RequestCredentials(ctx); err != nil {
		t.Fatalf("RequestCredentials: %v", err)
	}
}
