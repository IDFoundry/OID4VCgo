package wallet_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/http"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// An issued credential of either format is refused when IssuerRevocation
// says its signing certificate is revoked, or has no current CRL for
// it, and accepted with a clean CRL or none set.
func TestVerifyIssuedCredential_IssuerRevocation(t *testing.T) {
	ca, caKey := testcert.CAWithSubject(t, pkix.Name{CommonName: "revocation test CA", Country: []string{"SG"}})
	leaf, leafKey := testcert.Issue(t, &x509.Certificate{
		Subject:            pkix.Name{CommonName: "revocation test issuer", Country: []string{"SG"}},
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{mdoc.MDLDocumentSignerEKU},
	}, ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	f := newIssuedFixture(t, leaf, leafKey, roots)
	for format, c := range f.byFormat() {
		t.Run(format, func(t *testing.T) {
			testcert.RunRevocationCases(t, ca, caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
				_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
					Configuration: c.conf, Credential: c.credential, HolderKey: &f.holder.PublicKey,
					IssuerRoots: roots, IssuerRevocation: revocation,
				})
				return err
			})
		})
	}
	_, err := wallet.VerifyIssuedCredential(context.Background(), wallet.VerifyIssuedCredentialParams{
		Configuration: f.sdjwtConf, Credential: f.sdjwt, HolderKey: &f.holder.PublicKey,
		IssuerRoots: roots, IssuerRevocation: certrevocation.CRLs{},
	})
	if err == nil || !strings.Contains(err.Error(), "IssuerRevocation") {
		t.Errorf("CRLs without Lists: err = %v, want it refused as IssuerRevocation", err)
	}
}

// X5CVerifierRoots.Revocation refuses a Verifier whose request-signing
// certificate is revoked.
func TestX5CVerifierRoots_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "Verifier CA")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf, _ := testcert.Leaf(t, "verifier.example.com", ca, caKey)
	testcert.RunRevocationCases(t, ca, caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
		_, err := wallet.X5CVerifierRoots{Roots: roots, Revocation: revocation}.VerifyVerifierChain([][]byte{leaf.Raw})
		return err
	})
}

// Signed issuer metadata is refused when IssuerMetadataRevocation says
// its signer's certificate is revoked.
func TestFetchCredentialIssuerMetadata_Revocation(t *testing.T) {
	ca, caKey := testcert.CA(t, "metadata root")
	leaf, leafKey := testcert.Leaf(t, "metadata signer", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	issuerURL := serveMetadata(t, func(issuerURL, _ string) (string, string) {
		token, err := issuer.SignMetadataJWS(testMetadata(t, issuerURL), leafKey, jose.ES256, leaf)
		if err != nil {
			t.Fatal(err)
		}
		return "application/jwt", token
	})
	testcert.RunRevocationCases(t, ca, caKey, leaf, func(t *testing.T, revocation certrevocation.Checker) error {
		cfg := validConfig()
		cfg.IssuerMetadataRoots, cfg.IssuerMetadataRevocation = roots, revocation
		deps := validDependencies()
		deps.HTTP = http.DefaultClient
		w, err := wallet.New(cfg, deps)
		if err != nil {
			t.Fatalf("wallet.New: %v", err)
		}
		_, err = w.FetchCredentialIssuerMetadata(t.Context(), issuerURL)
		return err
	})
}

// New refuses a revocation Checker that can't check anything, for issuer
// metadata and for an X5CVerifierRoots VerifierTrust alike.
func TestNew_RefusesIncompleteRevocation(t *testing.T) {
	roots := x509.NewCertPool()
	for name, mutate := range map[string]func(*wallet.Config){
		"issuer metadata": func(c *wallet.Config) {
			c.IssuerMetadataRoots, c.IssuerMetadataRevocation = roots, certrevocation.CRLs{}
		},
		"verifier trust": func(c *wallet.Config) {
			c.VerifierTrust = &wallet.X5CVerifierRoots{Roots: roots, Revocation: certrevocation.CRLs{}}
		},
	} {
		cfg := validConfig()
		mutate(&cfg)
		deps := validDependencies()
		deps.HTTP = http.DefaultClient
		if _, err := wallet.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "Lists is required") {
			t.Errorf("%s: err = %v, want CRLs.Validate's refusal", name, err)
		}
	}
}

// Under AssuranceProduction, issuer metadata roots and an
// X5CVerifierRoots VerifierTrust need a revocation Checker, NoCheck{} to
// decline; AssuranceDevelopment takes either without one.
func TestNew_ProductionRequiresRevocationChoice(t *testing.T) {
	roots := x509.NewCertPool()
	for name, tc := range map[string]struct {
		set   func(*wallet.Config, certrevocation.Checker)
		field string
	}{
		"issuer metadata": {func(c *wallet.Config, r certrevocation.Checker) {
			c.IssuerMetadataRoots, c.IssuerMetadataRevocation = roots, r
		}, "issuer_metadata_revocation"},
		"verifier trust": {func(c *wallet.Config, r certrevocation.Checker) {
			c.VerifierTrust = wallet.X5CVerifierRoots{Roots: roots, Revocation: r}
		}, "X5CVerifierRoots.Revocation"},
		"verifier trust by pointer": {func(c *wallet.Config, r certrevocation.Checker) {
			c.VerifierTrust = &wallet.X5CVerifierRoots{Roots: roots, Revocation: r}
		}, "X5CVerifierRoots.Revocation"},
	} {
		cfg := validConfig()
		cfg.Assurance = wallet.AssuranceProduction
		cfg.Fetch.AllowLoopbackHTTP = false
		tc.set(&cfg, nil)
		if _, err := wallet.New(cfg, productionDependencies()); err == nil || !strings.Contains(err.Error(), tc.field) || !strings.Contains(err.Error(), "NoCheck") {
			t.Errorf("%s without revocation: err = %v, want it refused naming %s", name, err, tc.field)
		}
		tc.set(&cfg, certrevocation.NoCheck{})
		if _, err := wallet.New(cfg, productionDependencies()); err != nil {
			t.Errorf("%s declined: %v", name, err)
		}
		dev := validConfig()
		tc.set(&dev, nil)
		if _, err := wallet.New(dev, validDependencies()); err != nil {
			t.Errorf("%s without revocation in development: %v", name, err)
		}
	}
}
