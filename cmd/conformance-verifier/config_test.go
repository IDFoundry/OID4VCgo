package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/testcert"
)

func testPEMCertAndKey(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := testcert.SelfSigned(t, "conformance-verifier-test", &key.PublicKey, key)

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
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
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	got, err := loadConfig(path)
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
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			if _, err := loadConfig(path); err == nil {
				t.Fatalf("loadConfig = nil error, want error for missing %s", name)
			}
		})
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
