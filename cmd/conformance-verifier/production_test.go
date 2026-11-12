//go:build conformance_production

package main

import (
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
)

// productionTxTestSetup is newTxTestSetup under Config.Production: a
// sealed SQLite store in a temporary directory.
func productionTxTestSetup(t *testing.T) txTestSetup {
	t.Helper()
	s := newTxTestSetup(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s.cfg.Production = &ProductionConfig{
		DatabasePath: filepath.Join(t.TempDir(), "verifier.sqlite"),
		SealingKey:   base64.StdEncoding.EncodeToString(key),
	}
	return s
}

// TestTransactionsEngine_ProductionFlow runs the flow under
// verifier.AssuranceProduction, over the sealed SQLite store: every
// production check NewTransactions and VerifyResponse make passes, the
// suite runs' status policy (private addresses, a pinned TLS
// certificate) moved to the Accept.
func TestTransactionsEngine_ProductionFlow(t *testing.T) {
	s := productionTxTestSetup(t)
	checkTransactionsFlow(t, s)

	pinPEM, _ := testPEMCertAndKey(t)
	s = productionTxTestSetup(t)
	s.cfg.StatusListTrustAnchorsPEM = s.cfg.CredentialIssuerTrustAnchorsPEM
	s.cfg.StatusListTLSPinnedCertificatePEM = pinPEM
	s.cfg.StatusListAllowPrivate = true
	s.cfg.StatusReferenceOptional = true
	checkTransactionsFlow(t, s)
}

func TestTransactionsEngine_ProductionRefusals(t *testing.T) {
	for name, c := range map[string]struct {
		mutate func(*Config)
		want   string
	}{
		"a sealing key that isn't base64": {func(c *Config) { c.Production.SealingKey = "%%%" }, "sealing_key"},
		"a short sealing key":             {func(c *Config) { c.Production.SealingKey = "a2V5" }, "sealing_key"},
		"an unopenable database":          {func(c *Config) { c.Production.DatabasePath = filepath.Join(t.TempDir(), "missing", "v.sqlite") }, "v.sqlite"},
		// Production assurance refuses what development takes.
		"a self-signed client certificate": {func(c *Config) {
			c.ClientCertificatePEM, c.ClientPrivateKeyPEM = testPEMCertAndKey(t)
		}, "self-signed"},
		"a static issuer key": {func(c *Config) {
			c.CredentialIssuerTrustAnchorsPEM, c.CredentialIssuerJWK = "", baseTestConfig(t).CredentialIssuerJWK
		}, "KeySourceAssurance"},
	} {
		t.Run(name, func(t *testing.T) {
			s := productionTxTestSetup(t)
			c.mutate(&s.cfg)
			if _, _, err := newHandler(s.cfg); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("newHandler = %v, want an error mentioning %q", err, c.want)
			}
		})
	}
}
