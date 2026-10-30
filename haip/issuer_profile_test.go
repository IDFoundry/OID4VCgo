package haip_test

import (
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/haip"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

// withConfiguration is cfg with its one Credential Configuration
// changed by change.
func withConfiguration(cfg issuer.Config, change func(*issuer.CredentialConfiguration)) issuer.Config {
	configs := map[string]issuer.CredentialConfiguration{}
	for id, c := range cfg.CredentialConfigurationsSupported {
		change(&c)
		configs[id] = c
	}
	cfg.CredentialConfigurationsSupported = configs
	return cfg
}

// TestValidateIssuerConfig_RequiresES256Proofs: HAIP 1.0 §7 has issuers
// support ES256 for proofs and key attestations, so a proof type taking
// only another algorithm is refused (the audit's EdDSA-only PoC,
// inverted). One taking ES256 among others passes.
func TestValidateIssuerConfig_RequiresES256Proofs(t *testing.T) {
	cfg, deps := recommendedIssuer(t)
	setAlgs := func(algs ...string) issuer.Config {
		return withConfiguration(cfg, func(c *issuer.CredentialConfiguration) {
			ptc := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
			ptc.ProofSigningAlgValuesSupported = algs
			c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: ptc}
		})
	}
	if err := haip.ValidateIssuerConfig(setAlgs("EdDSA"), deps); err == nil || !strings.Contains(err.Error(), "ES256") {
		t.Errorf("an EdDSA-only proof type: %v, want it refused", err)
	}
	if err := haip.ValidateIssuerConfig(setAlgs("EdDSA", "ES256"), deps); err != nil {
		t.Errorf("a proof type taking ES256 and EdDSA: %v", err)
	}
}

// TestValidateIssuerConfig_RefusesUnauthenticatedPreAuthorizedCodes:
// with pre-authorized codes redeemed, a nil client authentication
// choice redeems them anonymously under development assurance, so HAIP
// refuses it as it does AnonymousPreAuthorizedCode; with none redeemed,
// nil is no choice at all. VerifiedPreAuthorizedCode passes.
func TestValidateIssuerConfig_RefusesUnauthenticatedPreAuthorizedCodes(t *testing.T) {
	cfg, deps := recommendedIssuer(t)
	if err := haip.ValidateIssuerConfig(cfg, deps); err != nil {
		t.Fatalf("no pre-authorized codes: %v", err)
	}
	deps.PreAuthorizedCodes = storage.NewPreAuthorizedCodeStore()
	if err := haip.ValidateIssuerConfig(cfg, deps); err == nil || !strings.Contains(err.Error(), "§4.4.1") {
		t.Errorf("pre-authorized codes with no client authentication choice: %v, want it refused", err)
	}
	cfg.PreAuthorizedCodeClientAuthentication = issuer.VerifiedPreAuthorizedCode{}
	if err := haip.ValidateIssuerConfig(cfg, deps); err != nil {
		t.Errorf("VerifiedPreAuthorizedCode: %v", err)
	}
}

// TestValidateIssuerConfig_ReportsEveryProblem: a configuration missing
// several HAIP requirements is told about all of them at once.
func TestValidateIssuerConfig_ReportsEveryProblem(t *testing.T) {
	cfg, deps := recommendedIssuer(t)
	cfg = withConfiguration(cfg, func(c *issuer.CredentialConfiguration) {
		c.Scope = ""
		ptc := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
		ptc.ProofSigningAlgValuesSupported = []string{"EdDSA"}
		c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: ptc}
	})
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.PreAuthorizedCodeClientAuthentication = issuer.AnonymousPreAuthorizedCode{}
	err := haip.ValidateIssuerConfig(cfg, deps)
	if err == nil {
		t.Fatal("ValidateIssuerConfig = nil error")
	}
	for _, want := range []string{"scope is required", "endpoints.nonce is required", "ES256", "anonymous pre-authorized code"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q doesn't report %q", err, want)
		}
	}
}

// TestIssuerProfileRunsInNew: with Config.Profile set to
// haip.IssuerProfile{}, issuer.New refuses what ValidateIssuerConfig
// refuses, under development assurance too; without it, plain OID4VCI
// takes the same configuration.
func TestIssuerProfileRunsInNew(t *testing.T) {
	for name, change := range map[string]func(*issuer.Config, *issuer.Dependencies){
		"no scope": func(c *issuer.Config, _ *issuer.Dependencies) {
			*c = withConfiguration(*c, func(cc *issuer.CredentialConfiguration) { cc.Scope = "" })
		},
		"no Nonce Endpoint": func(c *issuer.Config, d *issuer.Dependencies) {
			c.Endpoints.Nonce, c.Limits.NonceLifetime, c.Limits.MaxProofAge = fapi.URL{}, 0, issuer.MaxProductionProofAge
			d.Nonces = nil
		},
		"EdDSA proofs only": func(c *issuer.Config, _ *issuer.Dependencies) {
			*c = withConfiguration(*c, func(cc *issuer.CredentialConfiguration) {
				ptc := cc.ProofTypesSupported[oid4vci.ProofTypeJWT]
				ptc.ProofSigningAlgValuesSupported = []string{"EdDSA"}
				cc.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: ptc}
			})
		},
	} {
		cfg, deps := recommendedIssuer(t)
		change(&cfg, &deps)
		if _, err := issuer.New(cfg, deps); err != nil {
			t.Errorf("%s: plain OID4VCI: %v", name, err)
		}
		cfg.Profile = haip.IssuerProfile{}
		if _, err := issuer.New(cfg, deps); err == nil || !strings.Contains(err.Error(), "haip:") {
			t.Errorf("%s: issuer.New with haip.IssuerProfile = %v, want it refused", name, err)
		}
	}
}

// TestIssuerProfileReportsEachProblemInNew: issuer.New reports each
// problem HAIP finds on a line of its own, as it does its own.
func TestIssuerProfileReportsEachProblemInNew(t *testing.T) {
	cfg, deps := recommendedIssuer(t)
	cfg = withConfiguration(cfg, func(c *issuer.CredentialConfiguration) {
		c.Scope = ""
		ptc := c.ProofTypesSupported[oid4vci.ProofTypeJWT]
		ptc.ProofSigningAlgValuesSupported = []string{"EdDSA", "ES256"}
		c.ProofTypesSupported = map[string]oid4vci.ProofTypeConfiguration{oid4vci.ProofTypeJWT: ptc}
	})
	cfg.Endpoints.Nonce, cfg.Limits.MaxProofAge = fapi.URL{}, issuer.MaxProductionProofAge
	deps.Nonces = nil
	cfg.Profile = haip.IssuerProfile{}
	_, err := issuer.New(cfg, deps)
	if err == nil {
		t.Fatal("issuer.New = nil error")
	}
	lines := strings.Split(err.Error(), "\n")
	if len(lines) != 2 {
		t.Fatalf("issuer.New reported %d problems, want 2 (scope, Nonce Endpoint):\n%v", len(lines), err)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "issuer: profile: haip: ") {
			t.Errorf("line %q doesn't start with %q", line, "issuer: profile: haip: ")
		}
	}
}
