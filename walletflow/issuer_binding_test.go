package walletflow_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// trustedIssuer is the iss of a credential another issuer under the
// wallet's IssuerRoots signed: the shape of one the issuer the holder
// was sent to obtained elsewhere for the holder's keys and relayed.
const trustedIssuer = "https://trusted.issuer.example"

// notTheIssuer is in the error refusing its credential.
const notTheIssuer = "not the Credential Issuer"

// foreignIssWallet is a wallet over f's stores that receives an SD-JWT
// VC whose iss isn't the issuer it was requested from.
func foreignIssWallet(t *testing.T, f fixture) *walletflow.Wallet {
	t.Helper()
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, CredentialIssuers: []string{f.env.IssuerURL}, IssuerRoots: f.env.IssuerRoots,
		Development: true, AllowForeignIss: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

// An SD-JWT VC signed under the wallet's IssuerRoots but naming another
// issuer than the offer's credential_issuer isn't received, and nothing
// is stored.
func TestIssuance_RefusesAnotherIssuersCredential(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{SDJWTIss: trustedIssuer})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err == nil || !strings.Contains(err.Error(), notTheIssuer) || len(result.Credentials) != 0 {
		t.Fatalf("RequestCredentials = %+v, %v; want refused", result, err)
	}
	if held, _ := f.store.List(ctx); len(held) != 0 {
		t.Errorf("stored %d credentials", len(held))
	}
}

// A deferred credential is checked the same way when it's issued.
func TestDeferred_RefusesAnotherIssuersCredential(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{SDJWTIss: trustedIssuer, Defer: true})
	ctx := context.Background()
	s, err := f.w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err != nil || len(result.Deferred) != 1 {
		t.Fatalf("RequestCredentials = %+v, %v", result, err)
	}
	f.env.Decide(true)
	waitCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if stored, err := result.Deferred[0].Wait(waitCtx); err == nil || !strings.Contains(err.Error(), notTheIssuer) {
		t.Fatalf("Wait = %+v, %v; want refused", stored, err)
	}
	if held, _ := f.store.List(ctx); len(held) != 0 {
		t.Errorf("stored %d credentials", len(held))
	}
}

// Config.AllowForeignIss receives it.
func TestIssuance_AllowForeignIss(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{SDJWTIss: trustedIssuer})
	held := receive(t, f, foreignIssWallet(t, f), walletflowtest.SDJWTConfigurationID)
	if len(held) != 1 || held[0].Claims["iss"] != trustedIssuer {
		t.Fatalf("received %+v", held)
	}
}
