package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("conformance-issuer-test", nil)
	if err != nil {
		t.Fatalf("SelfSignedPEM: %v", err)
	}
	issuerKeyPEM, issuerCertPEM := conformancecert.TestKeyAndSelfSignedCertPEM(t, "conformance-issuer-test-credential-issuer")
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-1")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}
	requestDecryptionKeyPEM, err := conformancecert.GenerateECKeyPEM()
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
			AttesterJWKS:           attesterJWKS,
		},
		CredentialIssuerSigningKeyPEM:     issuerKeyPEM,
		CredentialIssuerCertificatePEM:    issuerCertPEM,
		CredentialRequestDecryptionKeyPEM: requestDecryptionKeyPEM,
		VCT:                               "urn:eudi:pid:1",
		Claims:                            map[string]string{"given_name": "Jean"},
		Scope:                             "IdentityCredential",
		CredentialConfigurationID:         "IdentityCredential",
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
		"listen_addr":                           func(c *Config) { c.ListenAddr = "" },
		"issuer":                                func(c *Config) { c.Issuer = "" },
		"client.id":                             func(c *Config) { c.Client.ID = "" },
		"client.redirect_uris":                  func(c *Config) { c.Client.RedirectURIs = nil },
		"client.expected_attester_issuer":       func(c *Config) { c.Client.ExpectedAttesterIssuer = "" },
		"client.attester_jwks":                  func(c *Config) { c.Client.AttesterJWKS = nil },
		"credential_issuer_signing_key_pem":     func(c *Config) { c.CredentialIssuerSigningKeyPEM = "" },
		"credential_issuer_certificate_pem":     func(c *Config) { c.CredentialIssuerCertificatePEM = "" },
		"credential_request_decryption_key_pem": func(c *Config) { c.CredentialRequestDecryptionKeyPEM = "" },
		"vct":                                   func(c *Config) { c.VCT = "" },
		"claims":                                func(c *Config) { c.Claims = nil },
		"scope":                                 func(c *Config) { c.Scope = "" },
		"credential_configuration_id":           func(c *Config) { c.CredentialConfigurationID = "" },
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

func TestLoadConfig_Client2IsOptional(t *testing.T) {
	cfg := baseTestConfig(t)
	if cfg.Client2 != nil {
		t.Fatalf("baseTestConfig already sets Client2: %+v", cfg.Client2)
	}
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
}

func TestLoadConfig_RejectsIncompleteClient2(t *testing.T) {
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-2")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}
	complete := ConfigClient{
		ID:                     "client2",
		RedirectURIs:           []string{"https://client2.example.com/callback"},
		ExpectedAttesterIssuer: "https://attester2.example.com",
		AttesterJWKS:           attesterJWKS,
	}
	cases := map[string]func(*ConfigClient){
		"client2.id":                       func(c *ConfigClient) { c.ID = "" },
		"client2.redirect_uris":            func(c *ConfigClient) { c.RedirectURIs = nil },
		"client2.expected_attester_issuer": func(c *ConfigClient) { c.ExpectedAttesterIssuer = "" },
		"client2.attester_jwks":            func(c *ConfigClient) { c.AttesterJWKS = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			c2 := complete
			mutate(&c2)
			cfg.Client2 = &c2
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want error for incomplete %s", name)
			}
		})
	}
}

func TestLoadConfig_AcceptsCompleteClient2(t *testing.T) {
	attesterKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate attester key: %v", err)
	}
	attesterJWKS, err := conformancecert.JWKSet(&attesterKey.PublicKey, "attester-2")
	if err != nil {
		t.Fatalf("JWKSet: %v", err)
	}
	cfg := baseTestConfig(t)
	cfg.Client2 = &ConfigClient{
		ID:                     "client2",
		RedirectURIs:           []string{"https://client2.example.com/callback"},
		ExpectedAttesterIssuer: "https://attester2.example.com",
		AttesterJWKS:           attesterJWKS,
	}
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.Client2 == nil || got.Client2.ID != "client2" {
		t.Fatalf("loadConfig round-trip lost Client2: %+v", got.Client2)
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
	key, err := cfg.credentialIssuerSigningKey()
	if err != nil {
		t.Fatalf("credentialIssuerSigningKey: %v", err)
	}
	cert, err := cfg.credentialIssuerCertificate()
	if err != nil {
		t.Fatalf("credentialIssuerCertificate: %v", err)
	}
	conformancecert.AssertMatchingPublicKey(t, key, cert.PublicKey)
}

func TestConfig_CredentialRequestDecryptionKey(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.credentialRequestDecryptionKey(); err != nil {
		t.Fatalf("credentialRequestDecryptionKey: %v", err)
	}
}

func TestConfig_IssuerURL(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.issuerURL(); err != nil {
		t.Fatalf("issuerURL: %v", err)
	}
}
