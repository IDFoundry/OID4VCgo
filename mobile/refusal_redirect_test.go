package mobile

import (
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The refusal's redirect_uri is taken once.
func TestTakeRefusalRedirect(t *testing.T) {
	w := &Wallet{refusalRedirect: "https://verifier.example/done"}
	if got := w.TakeRefusalRedirect(); got != "https://verifier.example/done" {
		t.Errorf("first take = %q", got)
	}
	if got := w.TakeRefusalRedirect(); got != "" {
		t.Errorf("second take = %q, want none", got)
	}
}

// Each StartPresentation's refusal redirect is its Operation's own, so
// presentations started concurrently can't swap them; the Wallet's
// holds the latest.
func TestTakeRefusalRedirect_PerOperation(t *testing.T) {
	w := &Wallet{}
	first, second := NewOperation(0), NewOperation(0)
	refused := func(uri string) error {
		return fmt.Errorf("walletflow: %w", &walletflow.RequestRefusedError{Code: "invalid_transaction_data", RedirectURI: uri})
	}
	w.recordRefusal(first, refused("https://first.example/done"))
	w.recordRefusal(second, refused("https://second.example/done"))
	if got := first.TakeRefusalRedirect(); got != "https://first.example/done" {
		t.Errorf("first Operation's = %q", got)
	}
	if got := second.TakeRefusalRedirect(); got != "https://second.example/done" {
		t.Errorf("second Operation's = %q", got)
	}
	if got := first.TakeRefusalRedirect(); got != "" {
		t.Errorf("first Operation's, again = %q, want none", got)
	}
	if got := w.TakeRefusalRedirect(); got != "https://second.example/done" {
		t.Errorf("Wallet's = %q, want the latest", got)
	}

	// Another error, or none, leaves no redirect.
	third := NewOperation(0)
	w.recordRefusal(third, errors.New("network"))
	w.recordRefusal(nil, nil)
	if got := third.TakeRefusalRedirect(); got != "" {
		t.Errorf("after another error = %q, want none", got)
	}
	if got := (*Operation)(nil).TakeRefusalRedirect(); got != "" {
		t.Errorf("nil Operation's = %q, want none", got)
	}
}

// verifier_redirect_schemes reaches walletflow, which refuses as
// invalid_input a scheme a Verifier's redirect is never followed with —
// http, a system app's, the wallet's own redirect_uri's — and one that
// isn't a scheme.
func TestNewWallet_VerifierRedirectSchemes(t *testing.T) {
	ks, cs := newGoKeyStore(), newGoCredentialStore()
	for _, schemes := range []string{`["http"]`, `["market"]`, `["com.example.wallet"]`, `["com example"]`} {
		_, err := NewWallet(`{"client_id":"c","redirect_uri":"com.example.wallet:/cb","verifier_redirect_schemes":`+schemes+`}`, ks, cs, nil)
		if code(err) != CodeInvalidInput {
			t.Errorf("verifier_redirect_schemes %s: %v, want invalid_input", schemes, err)
		}
	}
	if _, err := NewWallet(`{"client_id":"c","redirect_uri":"com.example.wallet:/cb","verifier_redirect_schemes":["https","com.example.verifier"]}`, ks, cs, nil); err != nil {
		t.Fatal(err)
	}
	wcfg, err := walletConfig(config{VerifierRedirectSchemes: []string{"com.example.verifier"}})
	if err != nil || !slices.Equal(wcfg.VerifierRedirectSchemes, []string{"com.example.verifier"}) {
		t.Errorf("walletflow.Config = %+v, %v", wcfg.VerifierRedirectSchemes, err)
	}
}
