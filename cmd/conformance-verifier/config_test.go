package main

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

func testPEMCertAndKey(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	certPEM, keyPEM, err := conformancecert.SelfSignedPEM("conformance-verifier-test", nil)
	if err != nil {
		t.Fatalf("SelfSignedPEM: %v", err)
	}
	return certPEM, keyPEM
}

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	certPEM, keyPEM := testPEMCertAndKey(t)
	tlsCertPEM, tlsKeyPEM := testPEMCertAndKey(t)
	return Config{
		ListenAddr:           ":8443",
		BaseURL:              "https://verifier.example.com",
		TLSCertificatePEM:    tlsCertPEM,
		TLSPrivateKeyPEM:     tlsKeyPEM,
		ClientCertificatePEM: certPEM,
		ClientPrivateKeyPEM:  keyPEM,
		CredentialIssuerJWK:  json.RawMessage(`{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}`),
		VCT:                  "urn:eudi:pid:1",
		Claims:               []string{"given_name", "family_name"},
	}
}

func TestLoadConfig_RoundTrips(t *testing.T) {
	cfg := baseTestConfig(t)
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.BaseURL != cfg.BaseURL || got.VCT != cfg.VCT {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]func(*Config){
		"listen_addr":           func(c *Config) { c.ListenAddr = "" },
		"base_url":              func(c *Config) { c.BaseURL = "" },
		"credential_issuer_jwk": func(c *Config) { c.CredentialIssuerJWK = nil },
		"vct":                   func(c *Config) { c.VCT = "" },
		"claims":                func(c *Config) { c.Claims = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want error for missing %s", name)
			}
		})
	}
}

func mdocTestConfig(t *testing.T) Config {
	t.Helper()
	trustAnchorPEM, _ := testPEMCertAndKey(t)
	cfg := baseTestConfig(t)
	cfg.CredentialFormat = "mso_mdoc"
	cfg.VCT = ""
	cfg.Claims = nil
	cfg.Doctype = "org.iso.18013.5.1.mDL"
	cfg.Namespace = "org.iso.18013.5.1"
	cfg.MdocClaims = []string{"given_name", "family_name"}
	cfg.MdocTrustAnchorPEM = trustAnchorPEM
	return cfg
}

func TestLoadConfig_MdocRoundTrips(t *testing.T) {
	cfg := mdocTestConfig(t)
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.CredentialFormat != "mso_mdoc" || got.Doctype != cfg.Doctype || got.Namespace != cfg.Namespace {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_RejectsMissingMdocFields(t *testing.T) {
	cases := map[string]func(*Config){
		"doctype":               func(c *Config) { c.Doctype = "" },
		"namespace":             func(c *Config) { c.Namespace = "" },
		"mdoc_claims":           func(c *Config) { c.MdocClaims = nil },
		"mdoc_trust_anchor_pem": func(c *Config) { c.MdocTrustAnchorPEM = "" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := mdocTestConfig(t)
			mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want error for missing %s", name)
			}
		})
	}
}

func TestLoadConfig_RejectsUnsupportedCredentialFormat(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.CredentialFormat = "jwt_vc_json"
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
		t.Fatal("loadConfig = nil error, want error for unsupported credential_format")
	}
}

func TestConfig_ClientCertificateAndKey(t *testing.T) {
	cfg := baseTestConfig(t)
	cert, key, err := cfg.clientCertificateAndKey()
	if err != nil {
		t.Fatalf("clientCertificateAndKey: %v", err)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		t.Fatalf("cert public key does not match parsed private key")
	}
}

func TestConfig_TLSCertificate(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.tlsCertificate(); err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
}
