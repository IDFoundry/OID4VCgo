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

func testECKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func testTLSCertAndKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	cert := testcert.SelfSigned(t, "conformance-wallet-vp-test", &key.PublicKey, key)
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
}

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	tlsCertPEM, tlsKeyPEM := testTLSCertAndKeyPEM(t)
	return Config{
		ListenAddr:                    ":8444",
		TLSCertificatePEM:             tlsCertPEM,
		TLSPrivateKeyPEM:              tlsKeyPEM,
		CredentialIssuerPrivateKeyPEM: testECKeyPEM(t),
		HolderPrivateKeyPEM:           testECKeyPEM(t),
		VCT:                           "urn:eudi:pid:1",
		Claims:                        map[string]string{"given_name": "Jean"},
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
	if got.VCT != cfg.VCT || len(got.Claims) != len(cfg.Claims) {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_RejectsMissingRequiredFields(t *testing.T) {
	cases := map[string]func(*Config){
		"listen_addr":                       func(c *Config) { c.ListenAddr = "" },
		"credential_issuer_private_key_pem": func(c *Config) { c.CredentialIssuerPrivateKeyPEM = "" },
		"holder_private_key_pem":            func(c *Config) { c.HolderPrivateKeyPEM = "" },
		"vct":                               func(c *Config) { c.VCT = "" },
		"claims":                            func(c *Config) { c.Claims = nil },
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

func TestConfig_CredentialIssuerKeyAndHolderPrivateKey(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.credentialIssuerKey(); err != nil {
		t.Fatalf("credentialIssuerKey: %v", err)
	}
	if _, err := cfg.holderPrivateKey(); err != nil {
		t.Fatalf("holderPrivateKey: %v", err)
	}
}

func TestConfig_TLSCertificate(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.tlsCertificate(); err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
}
