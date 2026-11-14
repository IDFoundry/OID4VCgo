package main

import (
	"encoding/json"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// withProduction is cfg with Config.Production set, its key
// attestations trusted by a fresh CA.
func withProduction(t *testing.T, cfg Config) Config {
	t.Helper()
	_, _, _, caPEM, err := conformancecert.GenerateSignerAndCert("backend-test-key-attestation", "backend-test-key-attestation-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Production = &ProductionConfig{DatabasePath: "issuer.sqlite", SealingKey: "c2VhbGluZw==", AccessTokenSigningKeyPEM: "key"}
	cfg.KeyAttestation = &conformanceconfig.KeyAttestationConfig{TrustAnchorPEM: caPEM}
	return cfg
}

func TestLoadConfig_Production(t *testing.T) {
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, withProduction(t, baseTestConfig(t)))); err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	// One of several instances sharing a PostgreSQL database.
	scaled := withProduction(t, baseTestConfig(t))
	scaled.Production.DatabasePath, scaled.Production.DatabaseURL = "", "postgres://localhost/issuer"
	scaled.Production.HorizontallyScaled, scaled.Production.NonceKey, scaled.Production.SweepInterval = true, "bm9uY2U=", "1s"
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, scaled)); err != nil {
		t.Fatalf("loadConfig, horizontally scaled: %v", err)
	}
	cases := map[string]func(*Config){
		"production.database_path":            func(c *Config) { c.Production.DatabasePath = "" },
		"both database_path and database_url": func(c *Config) { c.Production.DatabaseURL = "postgres://localhost/issuer" },
		"horizontally_scaled on SQLite":       func(c *Config) { c.Production.HorizontallyScaled, c.Production.NonceKey = true, "bm9uY2U=" },
		"horizontally_scaled without a nonce_key": func(c *Config) {
			c.Production.DatabasePath, c.Production.DatabaseURL, c.Production.HorizontallyScaled = "", "postgres://localhost/issuer", true
		},
		"a sweep_interval that isn't a duration":  func(c *Config) { c.Production.SweepInterval = "often" },
		"a sweep_interval that isn't positive":    func(c *Config) { c.Production.SweepInterval = "0s" },
		"production.sealing_key":                  func(c *Config) { c.Production.SealingKey = "" },
		"production.access_token_signing_key_pem": func(c *Config) { c.Production.AccessTokenSigningKeyPEM = "" },
		"key_attestation":                         func(c *Config) { c.KeyAttestation = nil },
		"key_attestation.trust_anchor_pem": func(c *Config) {
			c.KeyAttestation = &conformanceconfig.KeyAttestationConfig{TrustedJWK: json.RawMessage(`{}`)}
		},
		"key_attestation with both trusts": func(c *Config) { c.KeyAttestation.TrustedJWK = json.RawMessage(`{}`) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := withProduction(t, baseTestConfig(t))
			mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want error for %s", name)
			}
		})
	}
}

// The production setup's Wallet Attestation status lists are checked
// under every client's attester anchors, which declare they fetch
// nothing, as server.AssuranceProduction requires.
func TestAttesterRoots(t *testing.T) {
	_, _, _, caPEM, err := conformancecert.GenerateSignerAndCert("backend-test-attester", "backend-test-attester-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfg := baseTestConfig(t)
	if n := len(attesterRoots(cfg).Subjects()); n != 0 { //nolint:staticcheck // Subjects counts the pool's certificates, none from the system
		t.Errorf("attester_jwks clients: %d roots, want none", n)
	}
	cfg.Client2 = &ConfigClient{AttesterTrustAnchorsPEM: caPEM}
	if n := len(attesterRoots(cfg).Subjects()); n != 1 { //nolint:staticcheck // as above
		t.Errorf("%d roots, want client2's one", n)
	}
	if !(perClientAttesterAnchors{}).Capabilities().LiveFetchHardened {
		t.Error("perClientAttesterAnchors doesn't declare LiveFetchHardened")
	}
}

// Under Config.Production the Credential Configurations take jwt proofs
// requiring a key attestation and no attestation proof type, and key
// attestations are trusted by their x5c chain.
func TestAddKeyAttestationProofType_Production(t *testing.T) {
	cfg := withProduction(t, baseTestConfig(t))
	c := jwtProofCredentialConfiguration(cfg.Scope, "jwk", []string{"ES256"})
	verifier, err := addKeyAttestationProofType(cfg, &c)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := verifier.(issuer.X5CAttestationVerifier); !ok {
		t.Errorf("verifier = %T, want issuer.X5CAttestationVerifier", verifier)
	}
	if len(c.ProofTypesSupported) != 1 || c.ProofTypesSupported[oid4vci.ProofTypeJWT].KeyAttestationsRequired == nil {
		t.Errorf("proof_types_supported = %+v, want jwt alone, requiring a key attestation", c.ProofTypesSupported)
	}

	cfg.KeyAttestation.TrustAnchorPEM = "not a certificate"
	if _, err := addKeyAttestationProofType(cfg, &c); err == nil {
		t.Error("addKeyAttestationProofType = nil error for a trust_anchor_pem holding no certificate")
	}
}
