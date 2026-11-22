package walletflow

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// declined is c with certrevocation.NoCheck{} for each revocation
// Checker it leaves nil, VerifierTrust's included: the explicit choice
// New requires outside Development of a configuration testing something
// else. A c that receives credentials without deciding which issuers'
// offers it takes, or how old a status list may be, which New requires
// too, takes testIssuer's and testStatusMaxAge.
func declined(c Config) Config {
	if c.checkCredentialIssuerTrust() != nil && !c.AllowAnyCredentialIssuer {
		c.CredentialIssuers = []string{testIssuer}
	}
	if c.StatusMaxAge == 0 && !c.StatusAnyAge {
		c.StatusMaxAge = testStatusMaxAge
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

// testStatusMaxAge is the bound on a status list's age declined gives a
// configuration.
const testStatusMaxAge = 24 * time.Hour

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
	mdocOnly := Config{MdocIssuerRoots: pool("IACA"), CredentialIssuers: []string{testIssuer}, StatusMaxAge: testStatusMaxAge}
	if _, err := New(mdocOnly, deps); err == nil || !strings.Contains(err.Error(), "Config.IssuerRevocation") {
		t.Errorf("mdoc-only wallet without IssuerRevocation: New = %v", err)
	}
	mdocOnly.IssuerRevocation, mdocOnly.StatusRevocation = certrevocation.NoCheck{}, certrevocation.NoCheck{}
	if _, err := New(mdocOnly, deps); err != nil {
		t.Errorf("mdoc-only wallet, issuer roles declined: %v", err)
	}
	// So do a wallet's whose only issuer roots are a vct's.
	vctOnly := Config{IssuerRootsByVCT: map[string]*x509.CertPool{"urn:example:pid": pool("PID provider CA")}, CredentialIssuers: []string{testIssuer}, StatusMaxAge: testStatusMaxAge}
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

// Outside Development, a wallet receiving credentials bounds a status
// list's age (StatusMaxAge) or declines that (StatusAnyAge): neither is
// refused, naming the field, rather than accepting a list until its
// exp. Both, or a negative bound, are refused at every level. A wallet
// that receives nothing, and Development, need neither.
func TestNew_StatusMaxAgeChosen(t *testing.T) {
	receiving := func(development bool, maxAge time.Duration, anyAge bool) Config {
		c := declined(Config{IssuerRoots: x509.NewCertPool(), Development: development})
		c.StatusMaxAge, c.StatusAnyAge = maxAge, anyAge
		return c
	}
	for name, tc := range map[string]struct {
		cfg    Config
		refuse string
	}{
		"bounded":               {receiving(false, time.Hour, false), ""},
		"any age":               {receiving(false, 0, true), ""},
		"neither":               {receiving(false, 0, false), "Config.StatusMaxAge is required outside Development"},
		"both":                  {receiving(false, time.Hour, true), "not both"},
		"negative":              {receiving(false, -time.Hour, false), "must be positive"},
		"neither, Development":  {receiving(true, 0, false), ""},
		"both, Development":     {receiving(true, time.Hour, true), "not both"},
		"negative, Development": {receiving(true, -time.Hour, false), "must be positive"},
		"receiving nothing":     {Config{}, ""},
	} {
		_, err := New(tc.cfg, redirectDeps())
		switch {
		case tc.refuse == "" && err != nil:
			t.Errorf("%s: New = %v, want it taken", name, err)
		case tc.refuse != "" && (err == nil || !strings.Contains(err.Error(), tc.refuse)):
			t.Errorf("%s: New = %v, want it refused naming %q", name, err, tc.refuse)
		}
	}
}
