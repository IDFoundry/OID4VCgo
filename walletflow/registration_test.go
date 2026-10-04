package walletflow_test

import (
	"context"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// TestRegistration: a registered Verifier's registration is verified
// against the wallet's registrar roots and reported with what the
// request asks beyond it; it's ignored without registrar roots, and
// invalid against another registrar's.
func TestRegistration(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	ctx := context.Background()
	registered, err := f.env.StartRegisteredVerifier(dcql.Path{dcql.PathKey("given_name")})
	if err != nil {
		t.Fatal(err)
	}
	plain := f.env.StartVerifier(t)
	wallet := func(roots bool) *walletflow.Wallet {
		cfg := walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
			VerifierTrust: registered.Trust, Development: true,
		}
		if roots {
			cfg.RegistrarRoots = f.env.RegistrarRoots
		}
		w, err := walletflow.New(cfg, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	start := func(w *walletflow.Wallet, v *walletflowtest.Verifier, claims ...string) walletflow.Registration {
		t.Helper()
		_, link, err := v.Begin(dcql.Query{Credentials: []dcql.CredentialQuery{f.env.SDJWTQuery(t, "pid", claims...)}})
		if err != nil {
			t.Fatal(err)
		}
		p, err := w.StartPresentation(ctx, link)
		if err != nil {
			t.Fatal(err)
		}
		return p.Registration()
	}

	checked := wallet(true)
	if r := start(checked, registered, "given_name"); r.Status != walletflow.RegistrationVerified || r.Name != "Registered walletflowtest verifier" ||
		r.Purpose != "Testing" || len(r.Unregistered) != 0 {
		t.Errorf("within the registration: %+v", r)
	}
	r := start(checked, registered, "given_name", "family_name")
	if r.Status != walletflow.RegistrationVerified || len(r.Unregistered["pid"]) != 1 ||
		!slices.Equal(r.Unregistered["pid"][0], dcql.Path{dcql.PathKey("family_name")}) {
		t.Errorf("beyond the registration: %+v", r.Unregistered)
	}
	if r := start(checked, registered); r.Status != walletflow.RegistrationVerified || len(r.Unregistered["pid"]) != 1 || r.Unregistered["pid"][0] != nil {
		t.Errorf("every claim: %+v, want flagged in full", r.Unregistered)
	}
	if r := start(wallet(false), registered, "family_name"); r.Status != walletflow.RegistrationNone {
		t.Errorf("without registrar roots: %+v, want ignored", r)
	}

	// A Verifier with no registration, for a wallet that checks.
	other := walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		VerifierTrust: plain.Trust, Development: true, RegistrarRoots: f.env.RegistrarRoots,
	}
	w, err := walletflow.New(other, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	if r := start(w, plain.Verifier, "family_name"); r.Status != walletflow.RegistrationNone {
		t.Errorf("unregistered Verifier: %+v", r)
	}

	// Another registrar's roots: the registration doesn't verify.
	other.VerifierTrust, other.RegistrarRoots = registered.Trust, f.env.IssuerRoots
	w, err = walletflow.New(other, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP})
	if err != nil {
		t.Fatal(err)
	}
	if r := start(w, registered, "family_name"); r.Status != walletflow.RegistrationInvalid || r.Unregistered != nil {
		t.Errorf("another registrar: %+v, want invalid", r)
	}
}
