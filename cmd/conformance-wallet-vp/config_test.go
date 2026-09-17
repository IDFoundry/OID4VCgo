package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

func testECKeyPEM(t *testing.T) string {
	t.Helper()
	keyPEM, err := conformancecert.GenerateECKeyPEM()
	if err != nil {
		t.Fatalf("GenerateECKeyPEM: %v", err)
	}
	return keyPEM
}

// testECKeyAndCertPEM returns a fresh EC P-256 key plus a self-signed
// certificate wrapping that same key's public half — for
// CredentialIssuerPrivateKeyPEM/CredentialIssuerCertificatePEM, which
// must name the same key pair (Issue rejects a mismatch).
func testECKeyAndCertPEM(t *testing.T) (keyPEM, certPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM, err = conformancecert.ECKeyPEM(key)
	if err != nil {
		t.Fatalf("ECKeyPEM: %v", err)
	}
	certPEM, err = conformancecert.SelfSignedCertPEMForKey("test-credential-issuer", key)
	if err != nil {
		t.Fatalf("SelfSignedCertPEMForKey: %v", err)
	}
	return keyPEM, certPEM
}

func testTLSCertAndKeyPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	certPEM, keyPEM, err := conformancecert.SelfSignedPEM("conformance-wallet-vp-test", nil)
	if err != nil {
		t.Fatalf("SelfSignedPEM: %v", err)
	}
	return certPEM, keyPEM
}

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	tlsCertPEM, tlsKeyPEM := testTLSCertAndKeyPEM(t)
	issuerKeyPEM, issuerCertPEM := testECKeyAndCertPEM(t)
	return Config{
		ListenAddr:                     ":8444",
		TLSCertificatePEM:              tlsCertPEM,
		TLSPrivateKeyPEM:               tlsKeyPEM,
		CredentialIssuerPrivateKeyPEM:  issuerKeyPEM,
		CredentialIssuerCertificatePEM: issuerCertPEM,
		HolderPrivateKeyPEM:            testECKeyPEM(t),
		VCT:                            "urn:eudi:pid:1",
		Claims:                         map[string]string{"given_name": "Jean"},
	}
}

func TestLoadConfig_RoundTrips(t *testing.T) {
	cfg := baseTestConfig(t)
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
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
		"credential_issuer_certificate_pem": func(c *Config) { c.CredentialIssuerCertificatePEM = "" },
		"holder_private_key_pem":            func(c *Config) { c.HolderPrivateKeyPEM = "" },
		"vct":                               func(c *Config) { c.VCT = "" },
		"claims":                            func(c *Config) { c.Claims = nil },
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

func TestConfig_CredentialIssuerKeyAndHolderPrivateKey(t *testing.T) {
	cfg := baseTestConfig(t)
	issuerKey, err := cfg.credentialIssuerKey()
	if err != nil {
		t.Fatalf("credentialIssuerKey: %v", err)
	}
	if _, err := cfg.holderPrivateKey(); err != nil {
		t.Fatalf("holderPrivateKey: %v", err)
	}
	issuerCert, err := cfg.credentialIssuerCertificate()
	if err != nil {
		t.Fatalf("credentialIssuerCertificate: %v", err)
	}
	conformancecert.AssertMatchingPublicKey(t, issuerKey, issuerCert.PublicKey)
}

func TestConfig_TLSCertificate(t *testing.T) {
	cfg := baseTestConfig(t)
	if _, err := cfg.tlsCertificate(); err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
}
