package verifierapp_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gmrtd/gmrtd/cms"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// receiveInto runs issuance for e into a fresh wallet store.
func receiveInto(t *testing.T, env *demotest.Env, e passport.Evidence) walletapp.Store {
	t.Helper()
	ctx := context.Background()
	offer, err := env.Issuer.CreateTransaction(ctx, e)
	if err != nil {
		t.Fatalf("CreateTransaction: %v", err)
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP})
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	store := walletapp.Store{Dir: filepath.Join(t.TempDir(), "wallet")}
	for _, r := range received {
		if _, err := store.Save(r, time.Now()); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	return store
}

// present answers a fresh request in mode with the stored credential of
// format, and returns the verifier's outcome.
func present(t *testing.T, env *demotest.Env, store walletapp.Store, mode verifierapp.Mode, format string) *verifierapp.Outcome {
	t.Helper()
	id, link, err := env.Verifier.CreateRequest(mode)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	presentTo(t, env, store, link, format)
	outcome, ok := env.Verifier.Outcome(id)
	if !ok {
		t.Fatalf("verifier recorded no outcome (last rejection: %q)", env.Verifier.LastError(id))
	}
	return outcome
}

// presentTo answers the request at link with the stored credential of
// format.
func presentTo(t *testing.T, env *demotest.Env, store walletapp.Store, link, format string) {
	t.Helper()
	presented, err := walletapp.Present(context.Background(), link, store, walletapp.PresentOptions{Format: format, HTTP: env.HTTP})
	if err != nil {
		t.Fatalf("Present(%s): %v", format, err)
	}
	if len(presented.Credentials) != 1 {
		t.Fatalf("presented %v, want exactly one credential", presented.Credentials)
	}
}

// TestEndToEnd_TrustIssuer presents each format for the "trust the
// issuer" request: identity attributes accepted on the issuer's
// signature (chained to its demo CA) and the holder's key binding.
func TestEndToEnd_TrustIssuer(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := receiveInto(t, env, demotest.SyntheticEvidence())

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		t.Run(format, func(t *testing.T) {
			out := present(t, env, store, verifierapp.ModeIssuer, format)
			if out.Format != format || out.Claims[credential.FamilyName] != "DOE" {
				t.Errorf("outcome = %+v", out)
			}
			if out.ICAO != nil {
				t.Error("an issuer-mode request ran the ICAO check")
			}
			// Only what was asked for is disclosed.
			for _, withheld := range []string{credential.DocumentNumber, credential.ICAOSOD, credential.ICAODG2} {
				if _, ok := out.Claims[withheld]; ok {
					t.Errorf("%s was disclosed without being requested", withheld)
				}
			}
		})
	}
}

// TestEndToEnd_TrustICAO_SyntheticSODFails presents each format for the
// "trust only the country" request with synthetic evidence: the
// presentation itself verifies, but Passive Authentication over its
// (fake) SOD must fail — the demo issuer can't vouch for passport data
// on its own.
func TestEndToEnd_TrustICAO_SyntheticSODFails(t *testing.T) {
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	env := demotest.New(t, nil)
	env.StartVerifier(t, pool)
	store := receiveInto(t, env, demotest.SyntheticEvidence())

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		t.Run(format, func(t *testing.T) {
			out := present(t, env, store, verifierapp.ModeICAO, format)
			if out.ICAO == nil || out.ICAO.Verified {
				t.Fatalf("ICAO result = %+v, want a failed check", out.ICAO)
			}
			if _, ok := out.Claims[credential.ICAODG2]; ok {
				t.Error("icao_dg2 (the photo) was disclosed without being requested")
			}
			if _, ok := out.Claims[credential.FamilyName]; ok {
				t.Error("family_name was disclosed to an ICAO-only request")
			}
		})
	}
}

// TestEndToEnd_TrustICAO_Sample runs the ICAO path with a real passport
// when PASSPORT_VDC_SAMPLE points at one (outside this repository):
// issued from the verified upload, presented as SOD + DG1 only, and
// re-verified by the verifier against the ICAO master list. Logs
// nothing from the passport.
func TestEndToEnd_TrustICAO_Sample(t *testing.T) {
	path := os.Getenv("PASSPORT_VDC_SAMPLE")
	if path == "" {
		t.Skip("PASSPORT_VDC_SAMPLE not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read sample")
	}
	pool, err := cms.DefaultMasterList()
	if err != nil {
		t.Fatalf("DefaultMasterList: %v", err)
	}
	e, err := passport.Verify(data, pool, time.Now())
	if err != nil {
		t.Skip("sample doesn't verify")
	}
	env := demotest.New(t, pool)
	env.StartVerifier(t, pool)
	store := receiveInto(t, env, e)

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		t.Run(format, func(t *testing.T) {
			out := present(t, env, store, verifierapp.ModeICAO, format)
			if out.ICAO == nil || !out.ICAO.Verified {
				t.Fatal("ICAO Passive Authentication over the presented SOD + DG1 failed")
			}
			if out.ICAO.Identity.DocumentNumber != e.Identity.DocumentNumber {
				t.Error("identity from the presented DG1 differs from the passport's")
			}
		})
	}
}
