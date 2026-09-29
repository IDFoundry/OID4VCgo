package verifierapp_test

import (
	"bytes"
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
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
	presented, err := walletapp.Present(context.Background(), link, store, walletapp.PresentOptions{Format: format, HTTP: env.HTTP, VerifierTrust: env.VerifierTrust()})
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
			if got, ok := credential.PortraitJPEG(out.Claims); !ok || !bytes.Equal(got, demotest.SyntheticPortrait()) {
				t.Error("the portrait wasn't disclosed intact")
			}
			// Only what was asked for is disclosed.
			for _, withheld := range []string{credential.DocumentNumber, credential.PassportFile} {
				if _, ok := out.Claims[withheld]; ok {
					t.Errorf("%s was disclosed without being requested", withheld)
				}
			}
		})
	}
}

// TestEndToEnd_TrustIssuer_NoPortrait checks the portrait is asked for,
// not required: a credential from a passport without a usable face
// image still answers the issuer-mode request.
func TestEndToEnd_TrustIssuer_NoPortrait(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	e := demotest.SyntheticEvidence()
	e.Portrait = nil
	store := receiveInto(t, env, e)

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		t.Run(format, func(t *testing.T) {
			out := present(t, env, store, verifierapp.ModeIssuer, format)
			if out.Claims[credential.FamilyName] != "DOE" {
				t.Errorf("outcome = %+v", out)
			}
			if _, ok := credential.PortraitJPEG(out.Claims); ok {
				t.Error("a portrait was disclosed from a credential without one")
			}
		})
	}
}

// TestEndToEnd_TrustICAO_SyntheticFileFails presents each format for
// the "trust only the country" request with synthetic evidence: the
// presentation itself verifies, but re-verifying its (fake) passport
// file must fail — the demo issuer can't vouch for passport data on its
// own.
func TestEndToEnd_TrustICAO_SyntheticFileFails(t *testing.T) {
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
			if out.ICAO.Error != passport.ErrUnreadable.Error() {
				t.Errorf("ICAO error = %q, want the fixed unreadable-file error", out.ICAO.Error)
			}
			if _, ok := out.Claims[credential.PassportFile]; !ok {
				t.Error("the passport file wasn't disclosed")
			}
			if _, ok := credential.PortraitJPEG(out.Claims); ok {
				t.Error("the portrait was disclosed to an ICAO-only request")
			}
			if _, ok := out.Claims[credential.FamilyName]; ok {
				t.Error("family_name was disclosed to an ICAO-only request")
			}
		})
	}
}

// TestEndToEnd_TrustICAO_Sample runs the ICAO path with a real passport
// when PASSPORT_VDC_SAMPLE points at one (outside this repository):
// issued from the verified upload, presented as the passport file, and
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
				t.Fatal("re-verifying the presented passport file failed")
			}
			if out.ICAO.Identity.DocumentNumber != e.Identity.DocumentNumber {
				t.Error("identity from the presented file differs from the passport's")
			}
			if !bytes.Equal(out.ICAO.Portrait, e.Portrait) || out.ICAO.ChipAuthenticity != e.Checks.ChipAuthenticity {
				t.Error("portrait or chip authenticity from the presented file differs from the issuer's")
			}
		})
	}
}

// TestEndToEnd_Revocation checks each credential references the issuer's
// Token Status List and is accepted while its entry is VALID; once the
// issuer revokes the mdoc (through its revocation page), presenting it
// is rejected, while the still-valid SD-JWT VC is accepted.
func TestEndToEnd_Revocation(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := receiveInto(t, env, demotest.SyntheticEvidence())

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, store, verifierapp.ModeIssuer, format); out.Status != "valid" {
			t.Fatalf("%s: Status = %q before revocation, want valid", format, out.Status)
		}
	}

	revoked := ""
	for _, s := range env.Issuer.IssuedStatuses() {
		if s.Format == "mso_mdoc" {
			revoked = s.Handle
		}
	}
	if revoked == "" {
		t.Fatal("the issuer recorded no mso_mdoc credential")
	}
	resp, err := env.HTTP.PostForm(env.IssuerURL+"/status/revoke", url.Values{"handle": {revoked}})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_ = resp.Body.Close()

	id, link, err := env.Verifier.CreateRequest(verifierapp.ModeIssuer)
	if err != nil {
		t.Fatalf("CreateRequest: %v", err)
	}
	// The wallet is told only that its answer wasn't accepted; the
	// verifier records why.
	_, err = walletapp.Present(context.Background(), link, store, walletapp.PresentOptions{Format: "mso_mdoc", HTTP: env.HTTP, VerifierTrust: env.VerifierTrust()})
	if err == nil || strings.Contains(err.Error(), "revoked") {
		t.Fatalf("presenting the revoked mdoc: error = %v, want a generic rejection", err)
	}
	if reason := env.Verifier.LastError(id); !strings.Contains(reason, "revoked") {
		t.Fatalf("the verifier recorded %q, want the revocation", reason)
	}
	if out := present(t, env, store, verifierapp.ModeIssuer, "dc+sd-jwt"); out.Status != "valid" {
		t.Errorf("the unrevoked SD-JWT VC: Status = %q, want valid", out.Status)
	}
}

// TestEndToEnd_ExpiredPassport: an expired passport's data is still
// authentic, so it's issued and presented like any other.
func TestEndToEnd_ExpiredPassport(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	e := demotest.SyntheticEvidence()
	e.Identity.ExpiryDate = time.Now().AddDate(-1, 0, 0)
	store := receiveInto(t, env, e)

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, store, verifierapp.ModeIssuer, format); out.Claims[credential.FamilyName] != "DOE" {
			t.Errorf("%s: outcome = %+v", format, out)
		}
	}
}
