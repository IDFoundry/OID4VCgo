package main

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-issuer-test", nil)
	if err != nil {
		t.Fatalf("SelfSignedPEM: %v", err)
	}
	issuerKeyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		t.Fatalf("GenerateECKeyPEM: %v", err)
	}
	return Config{
		ListenAddr:        ":8443",
		Issuer:            "https://issuer.example.com",
		TLSCertificatePEM: tlsCertPEM,
		TLSPrivateKeyPEM:  tlsKeyPEM,
		Client: ConfigClient{
			ID:                     "client1",
			RedirectURIs:           []string{"https://client.example.com/callback"},
			ExpectedAttesterIssuer: "https://attester.example.com",
		},
		CredentialIssuerSigningKeyPEM: issuerKeyPEM,
		VCT:                           "urn:eudi:pid:1",
		Claims:                        map[string]string{"given_name": "Jean"},
		Scope:                         "IdentityCredential",
		CredentialConfigurationID:     "IdentityCredential",
	}
}

func TestLoadConfig_RoundTrips(t *testing.T) {
	cfg := baseTestConfig(t)
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.Issuer != cfg.Issuer || got.VCT != cfg.VCT || got.Client.ID != cfg.Client.ID {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_DefaultsSubject(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.DefaultSubject = ""
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.DefaultSubject == "" {
		t.Fatalf("DefaultSubject was not defaulted")
	}
}

func TestLoadConfig_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]func(*Config){
		"listen_addr":                       func(c *Config) { c.ListenAddr = "" },
		"issuer":                            func(c *Config) { c.Issuer = "" },
		"client.id":                         func(c *Config) { c.Client.ID = "" },
		"client.redirect_uris":              func(c *Config) { c.Client.RedirectURIs = nil },
		"client.expected_attester_issuer":   func(c *Config) { c.Client.ExpectedAttesterIssuer = "" },
		"credential_issuer_signing_key_pem": func(c *Config) { c.CredentialIssuerSigningKeyPEM = "" },
		"vct":                               func(c *Config) { c.VCT = "" },
		"claims":                            func(c *Config) { c.Claims = nil },
		"scope":                             func(c *Config) { c.Scope = "" },
		"credential_configuration_id":       func(c *Config) { c.CredentialConfigurationID = "" },
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

func TestConfig_TLSCertificate(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.tlsCertificate(); err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
}

func TestConfig_CredentialIssuerSigningKey(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.credentialIssuerSigningKey(); err != nil {
		t.Fatalf("credentialIssuerSigningKey: %v", err)
	}
}

func TestConfig_IssuerURL(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.issuerURL(); err != nil {
		t.Fatalf("issuerURL: %v", err)
	}
}
