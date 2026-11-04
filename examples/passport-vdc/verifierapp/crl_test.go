package verifierapp_test

import (
	"context"
	"crypto/x509"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/verifierapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
)

// TestEndToEnd_RevokedDocumentSigner: once the issuer revokes its
// document signer, and the verifier has the CA's new CRL, a credential
// the revoked signer signed is refused, in either format, for the
// revocation; one issued since, by the new signer, is accepted.
func TestEndToEnd_RevokedDocumentSigner(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	store := receiveInto(t, env, demotest.SyntheticEvidence())
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, store, verifierapp.ScenarioSignup, format); out.Status != "valid" {
			t.Fatalf("%s before the revocation: Status = %q", format, out.Status)
		}
	}

	// The status page's form; the demo has the issuer tell its verifier
	// to fetch the CRL then (issuerapp.Config.OnSignerRevoked).
	req, err := http.NewRequest(http.MethodPost, env.IssuerURL+"/demo/signer/revoke", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(env.Issuer.RevokedSigners()) != 1 {
		t.Fatal("the document signer wasn't revoked")
	}

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		id, link, err := env.Verifier.CreateRequest(verifierapp.ScenarioSignup)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := walletapp.Present(context.Background(), link, store, walletapp.PresentOptions{Format: format, HTTP: env.HTTP, VerifierTrust: env.VerifierTrust()}); err == nil {
			t.Errorf("%s signed by the revoked signer was accepted", format)
		}
		// The same credential was accepted before: what changed is its
		// signer's revocation, which the verifier library reports as
		// an issuer it doesn't trust (its fixed descriptions name no
		// cause).
		if reason := env.Verifier.LastError(id); !strings.Contains(reason, "untrusted_issuer") {
			t.Errorf("%s: the verifier recorded %q, want its issuer refused", format, reason)
		}
	}

	fresh := receiveInto(t, env, demotest.SyntheticEvidence())
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, fresh, verifierapp.ScenarioSignup, format); out.Status != "valid" {
			t.Errorf("%s from the new signer: Status = %q", format, out.Status)
		}
	}
}

// TestEndToEnd_RevokedDocumentSignerStatus: revoking the document
// signer revokes its credentials on the status list too, so a verifier
// that hasn't fetched the CA's new CRL yet still refuses them, on their
// status, at once.
func TestEndToEnd_RevokedDocumentSignerStatus(t *testing.T) {
	// Not told to fetch the CRL: the verifier keeps the one it holds,
	// which doesn't list the signer.
	env := demotest.New(t, nil, func(c *issuerapp.Config) { c.OnSignerRevoked = nil })
	env.StartVerifier(t, nil)
	store := receiveInto(t, env, demotest.SyntheticEvidence())
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, store, verifierapp.ScenarioSignup, format); out.Status != "valid" {
			t.Fatalf("%s before the revocation: Status = %q", format, out.Status)
		}
	}

	req, err := http.NewRequest(http.MethodPost, env.IssuerURL+"/demo/signer/revoke", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := env.HTTP.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || len(env.Issuer.RevokedSigners()) != 1 {
		t.Fatalf("revoking the document signer: status %d", resp.StatusCode)
	}

	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		id, link, err := env.Verifier.CreateRequest(verifierapp.ScenarioSignup)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := walletapp.Present(context.Background(), link, store, walletapp.PresentOptions{Format: format, HTTP: env.HTTP, VerifierTrust: env.VerifierTrust()}); err == nil {
			t.Errorf("%s signed by the revoked signer was accepted", format)
		}
		if reason := env.Verifier.LastError(id); !strings.Contains(reason, "revoked") {
			t.Errorf("%s: the verifier recorded %q, want the credential's revocation", format, reason)
		}
	}

	fresh := receiveInto(t, env, demotest.SyntheticEvidence())
	for _, format := range []string{"mso_mdoc", "dc+sd-jwt"} {
		if out := present(t, env, fresh, verifierapp.ScenarioSignup, format); out.Status != "valid" {
			t.Errorf("%s from the new signer: Status = %q", format, out.Status)
		}
	}
}

// TestCRLs_VerifierCAs: each CA a wallet trusts for the verifier serves
// its CRL, signed by it, at the distribution point it names.
func TestCRLs_VerifierCAs(t *testing.T) {
	env := demotest.New(t, nil)
	env.StartVerifier(t, nil)
	for _, ca := range []*x509.Certificate{env.Verifier.VerifierCACertificate(), env.Verifier.ReaderCACertificate(), env.Verifier.RegistrarCACertificate()} {
		if len(ca.CRLDistributionPoints) != 1 || !strings.HasPrefix(ca.CRLDistributionPoints[0], env.VerifierURL+"/") {
			t.Fatalf("%q names %v", ca.Subject.CommonName, ca.CRLDistributionPoints)
		}
		resp, err := env.HTTP.Get(ca.CRLDistributionPoints[0])
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != democrl.ContentType {
			t.Fatalf("%s: %d %s %v", ca.CRLDistributionPoints[0], resp.StatusCode, resp.Header.Get("Content-Type"), err)
		}
		list, err := x509.ParseRevocationList(body)
		if err != nil || list.CheckSignatureFrom(ca) != nil || list.Number == nil || len(list.RevokedCertificateEntries) != 0 {
			t.Errorf("%q's CRL: %v; want an empty list it signed, with a number", ca.Subject.CommonName, err)
		}
	}
	if dp := env.Verifier.VerifierCACertificate().CRLDistributionPoints; !slices.Equal(dp, []string{env.VerifierURL + verifierapp.VerifierCRLPath}) {
		t.Errorf("the verifier CA names %v", dp)
	}
}
