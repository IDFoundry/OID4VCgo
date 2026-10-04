package verifierapp_test

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// TestRegistrations: a wallet trusting the demo registrar sees each
// trusted relying party's registration, which covers what its scenario
// asks — except the over-asking shop's, registered only for the age
// check, whose name claims it flags. CheapFlights is refused before
// any registration is read.
func TestRegistrations(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	cfg := env.WalletConfig()
	registrars := x509.NewCertPool()
	registrars.AddCert(env.Verifier.RegistrarCACertificate())
	w, err := walletflow.New(walletflow.Config{
		ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, IssuerRoots: cfg.IssuerRoots, Development: true,
		VerifierTrust: env.VerifierTrust(), RegistrarRoots: registrars,
	}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: cfg.Provider, HTTP: env.HTTP,
	})
	if err != nil {
		t.Fatal(err)
	}
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	s, err := w.StartIssuance(ctx, offer.URI)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := s.BeginAuthorization(ctx)
	if err != nil {
		t.Fatal(err)
	}
	loc, err := walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode}.Redirect(ctx, authURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CompleteAuthorization(ctx, loc.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RequestCredentials(ctx); err != nil {
		t.Fatal(err)
	}

	for _, sc := range verifierapp.Scenarios {
		info, _ := sc.Info()
		t.Run(string(sc), func(t *testing.T) {
			_, link, err := env.Verifier.CreateRequest(sc)
			if err != nil {
				t.Fatal(err)
			}
			p, err := w.StartPresentation(ctx, link)
			if !info.Trusted {
				if !errors.Is(err, wallet.ErrUntrustedVerifier) {
					t.Fatalf("StartPresentation = %v, want the untrusted verifier refused", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _, _ = p.Decline(ctx) }()
			reg := p.Registration()
			if reg.Status != walletflow.RegistrationVerified || reg.Name != info.Verifier {
				t.Fatalf("registration = %+v, want verified as %s", reg, info.Verifier)
			}
			over := 0
			for _, paths := range reg.Unregistered {
				over += len(paths)
			}
			switch {
			case sc == verifierapp.ScenarioOverAsking && over != 4:
				// given_name and family_name, in each format.
				t.Errorf("unregistered = %v, want the two name claims of each format", reg.Unregistered)
			case sc != verifierapp.ScenarioOverAsking && over != 0:
				t.Errorf("unregistered = %v, want none", reg.Unregistered)
			}
		})
	}
}
