package issuerapp_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/credential"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/demotest"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/issuerapp"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/walletapp"
	"github.com/idfoundry/oid4vcgo/haip"
)

// fetchCRL gets the issuer's CRL and checks it's one its CA signed, in
// the form relying parties take: complete and direct, current, with a
// CRL number.
func fetchCRL(t *testing.T, env *demotest.Env) *x509.RevocationList {
	t.Helper()
	resp, err := env.HTTP.Get(env.IssuerURL + issuerapp.CRLPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != democrl.ContentType {
		t.Fatalf("GET %s: %d %s", issuerapp.CRLPath, resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatalf("the CRL doesn't parse: %v", err)
	}
	if err := list.CheckSignatureFrom(env.Issuer.IssuerCACertificate()); err != nil {
		t.Fatalf("the CRL isn't the CA's: %v", err)
	}
	now := time.Now()
	if list.Number == nil || list.ThisUpdate.After(now) || !list.NextUpdate.After(now) || list.NextUpdate.Sub(list.ThisUpdate) != democrl.Validity {
		t.Errorf("CRL number %v, thisUpdate %v, nextUpdate %v: want a number, current now for %v", list.Number, list.ThisUpdate, list.NextUpdate, democrl.Validity)
	}
	for _, ext := range list.Extensions {
		// No delta CRL indicator or issuing distribution point: a
		// complete, direct list.
		if id := ext.Id.String(); id == "2.5.29.27" || id == "2.5.29.28" {
			t.Errorf("the CRL carries extension %s", id)
		}
	}
	return list
}

// TestRevokeDocumentSigner_CRL: the CA serves its CRL at the
// distribution point its certificates name; revoking the document
// signer from the status page lists it there, under a higher CRL
// number, and the issuer signs with a new signer its CA certified.
func TestRevokeDocumentSigner_CRL(t *testing.T) {
	ctx := context.Background()
	env := demotest.New(t, nil)
	old := env.Issuer.IssuerCertificate()
	if !slices.Equal(env.Issuer.IssuerCACertificate().CRLDistributionPoints, []string{env.IssuerURL + issuerapp.CRLPath}) ||
		!slices.Equal(old.CRLDistributionPoints, []string{env.IssuerURL + issuerapp.CRLPath}) {
		t.Fatalf("the CA and document signer name %v and %v, not the CA's CRL", env.Issuer.IssuerCACertificate().CRLDistributionPoints, old.CRLDistributionPoints)
	}
	before := fetchCRL(t, env)
	if len(before.RevokedCertificateEntries) != 0 {
		t.Fatalf("a new CA's CRL lists %d certificates", len(before.RevokedCertificateEntries))
	}
	if again := fetchCRL(t, env); !bytes.Equal(again.Raw, before.Raw) {
		t.Error("a second fetch got a new list without a revocation or half its validity passing")
	}

	resp, err := env.HTTP.Do(revokeSigner(t, env, env.IssuerURL))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Request.URL.Path != "/demo/status" {
		t.Fatalf("revoking ended at %s, want the status page", resp.Request.URL)
	}

	after := fetchCRL(t, env)
	if after.Number.Cmp(before.Number) <= 0 || after.ThisUpdate.Before(before.ThisUpdate) {
		t.Errorf("CRL number %v (thisUpdate %v) after the revocation, not past %v (%v)", after.Number, after.ThisUpdate, before.Number, before.ThisUpdate)
	}
	if !slices.ContainsFunc(after.RevokedCertificateEntries, func(e x509.RevocationListEntry) bool { return e.SerialNumber.Cmp(old.SerialNumber) == 0 }) {
		t.Fatal("the CRL doesn't list the revoked document signer")
	}
	rotated := env.Issuer.IssuerCertificate()
	if rotated.Equal(old) || rotated.CheckSignatureFrom(env.Issuer.IssuerCACertificate()) != nil {
		t.Fatal("no new document signer from the CA")
	}

	// New credentials are signed by the new signer.
	offer, err := env.Issuer.CreateTransaction(ctx, demotest.SyntheticEvidence())
	if err != nil {
		t.Fatal(err)
	}
	received, err := walletapp.Receive(ctx, env.WalletConfig(), offer.URI, walletapp.HeadlessApprover{HTTP: env.HTTP, Code: offer.ConfirmationCode})
	if err != nil {
		t.Fatalf("receiving after the revocation: %v", err)
	}
	for _, r := range received {
		if r.ConfigurationID != issuerapp.MdocConfigurationID {
			continue
		}
		wire, err := base64.RawURLEncoding.DecodeString(r.Credential)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := mdoc.UnmarshalIssuerSigned(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := mdoc.Verify(signed, credential.DocType, rotated.PublicKey, haip.RecommendedCOSEAlgorithm, mdoc.VerifyOptions{}); err != nil {
			t.Errorf("the mdoc issued after the revocation isn't the new signer's: %v", err)
		}
	}
}

// TestRevokeDocumentSigner_RefusesCrossOrigin: another site can't revoke
// the document signer through a visitor's browser.
func TestRevokeDocumentSigner_RefusesCrossOrigin(t *testing.T) {
	env := demotest.New(t, nil)
	old := env.Issuer.IssuerCertificate()
	resp, err := env.HTTP.Do(revokeSigner(t, env, "https://attacker.example"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !env.Issuer.IssuerCertificate().Equal(old) || len(env.Issuer.RevokedSigners()) != 0 {
		t.Errorf("a cross-origin revocation: status %d, signer replaced %v", resp.StatusCode, !env.Issuer.IssuerCertificate().Equal(old))
	}
}

// revokeSigner is the status page's revoke-signer form post, from
// origin.
func revokeSigner(t *testing.T, env *demotest.Env, origin string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, env.IssuerURL+"/demo/signer/revoke", strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", origin)
	return req
}
