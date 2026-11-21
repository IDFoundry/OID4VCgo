package walletflow

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// declined is c with certrevocation.NoCheck{} for each revocation
// Checker it leaves nil, VerifierTrust's included: the explicit choice
// New requires outside Development of a configuration testing something
// else. A c that receives credentials without deciding which issuers'
// offers it takes, which New requires too, takes testIssuer's.
func declined(c Config) Config {
	if c.checkCredentialIssuerTrust() != nil && !c.AllowAnyCredentialIssuer {
		c.CredentialIssuers = []string{testIssuer}
	}
	for _, field := range []*certrevocation.Checker{
		&c.IssuerRevocation, &c.StatusRevocation, &c.IssuerMetadataRevocation, &c.RegistrarRevocation, &c.MdocReaderRevocation,
	} {
		if *field == nil {
			*field = certrevocation.NoCheck{}
		}
	}
	switch v := c.VerifierTrust.(type) {
	case wallet.X5CVerifierRoots:
		if v.Revocation == nil {
			v.Revocation = certrevocation.NoCheck{}
		}
		c.VerifierTrust = v
	case *wallet.X5CVerifierRoots:
		if v != nil && v.Revocation == nil {
			cp := *v
			cp.Revocation = certrevocation.NoCheck{}
			c.VerifierTrust = &cp
		}
	}
	return c
}

// Outside Development, each trust role in use needs a revocation
// Checker, certrevocation.NoCheck{} to decline: a nil one is refused,
// naming the field, rather than silently checking nothing. A role not
// in use needs none, and Development needs none at all.
// testIssuer is the Credential Issuer whose offers declined has a
// configuration take.
const testIssuer = "https://issuer.example"

func TestNew_RevocationChosen(t *testing.T) {
	deps := redirectDeps()
	pool := func(name string) *x509.CertPool {
		ca, _ := testcert.CA(t, name)
		p := x509.NewCertPool()
		p.AddCert(ca)
		return p
	}
	full := func() Config {
		return declined(Config{
			IssuerRoots: pool("issuer CA"), IssuerMetadataRoots: pool("metadata CA"),
			VerifierTrust: wallet.X5CVerifierRoots{Roots: pool("verifier CA")}, RegistrarRoots: pool("registrar CA"),
			MdocReaderRoots: pool("reader CA"),
		})
	}
	if _, err := New(full(), deps); err != nil {
		t.Fatalf("every role declined: %v", err)
	}
	for field, unset := range map[string]func(*Config){
		"Config.IssuerRevocation":         func(c *Config) { c.IssuerRevocation = nil },
		"Config.StatusRevocation":         func(c *Config) { c.StatusRevocation = nil },
		"Config.IssuerMetadataRevocation": func(c *Config) { c.IssuerMetadataRevocation = nil },
		"Config.RegistrarRevocation":      func(c *Config) { c.RegistrarRevocation = nil },
		"Config.MdocReaderRevocation":     func(c *Config) { c.MdocReaderRevocation = nil },
		"X5CVerifierRoots.Revocation": func(c *Config) {
			v := c.VerifierTrust.(wallet.X5CVerifierRoots)
			v.Revocation = nil
			c.VerifierTrust = v
		},
		"X5CVerifierRoots.Revocation by pointer": func(c *Config) {
			v := c.VerifierTrust.(wallet.X5CVerifierRoots)
			v.Revocation = nil
			c.VerifierTrust = &v
		},
	} {
		cfg := full()
		unset(&cfg)
		want := strings.TrimSuffix(field, " by pointer")
		_, err := New(cfg, deps)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "certrevocation.NoCheck{}") {
			t.Errorf("%s nil: New = %v, want it refused naming the field and NoCheck", field, err)
		}
		cfg.Development = true
		if _, err := New(cfg, deps); err != nil {
			t.Errorf("%s nil in Development: New = %v, want it taken", field, err)
		}
	}
	// Only the roles in use need one: an mdoc-only wallet's issuer roles
	// and nothing else.
	mdocOnly := Config{MdocIssuerRoots: pool("IACA"), CredentialIssuers: []string{testIssuer}}
	if _, err := New(mdocOnly, deps); err == nil || !strings.Contains(err.Error(), "Config.IssuerRevocation") {
		t.Errorf("mdoc-only wallet without IssuerRevocation: New = %v", err)
	}
	mdocOnly.IssuerRevocation, mdocOnly.StatusRevocation = certrevocation.NoCheck{}, certrevocation.NoCheck{}
	if _, err := New(mdocOnly, deps); err != nil {
		t.Errorf("mdoc-only wallet, issuer roles declined: %v", err)
	}
	// So do a wallet's whose only issuer roots are a vct's.
	vctOnly := Config{IssuerRootsByVCT: map[string]*x509.CertPool{"urn:example:pid": pool("PID provider CA")}, CredentialIssuers: []string{testIssuer}}
	if _, err := New(vctOnly, deps); err == nil || !strings.Contains(err.Error(), "Config.IssuerRevocation") {
		t.Errorf("vct-only wallet without IssuerRevocation: New = %v", err)
	}
	vctOnly.IssuerRevocation, vctOnly.StatusRevocation = certrevocation.NoCheck{}, certrevocation.NoCheck{}
	if _, err := New(vctOnly, deps); err != nil {
		t.Errorf("vct-only wallet, issuer roles declined: %v", err)
	}
	// A wallet with no roots has no role to choose for.
	if _, err := New(Config{}, deps); err != nil {
		t.Errorf("a wallet with no roots: %v", err)
	}
}
