package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
	"github.com/idfoundry/oid4vcgo/wallet"
)

func productionTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := baseTestConfig(t)
	ca, err := conformancecrl.NewAuthority("verifier-ca", conformancecrl.URL("crl.test", "verifier-ca"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Engine, cfg.Assurance = engineWalletflow, assuranceProduction
	cfg.VerifierTrustAnchorsPEM = ca.CertPEM
	cfg.VerifierCRL = &conformancecrl.Trust{DistributionPoints: []conformancecrl.DistributionPoint{ca.DistributionPoint()}, TLSTrustAnchorsPEM: ca.CertPEM}
	return cfg
}

func TestLoadConfig_Assurance(t *testing.T) {
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, productionTestConfig(t))); err != nil {
		t.Fatalf("production config: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"unknown assurance":   func(c *Config) { c.Assurance = "staging" },
		"wallet engine":       func(c *Config) { c.Engine = engineWallet },
		"no verifier anchors": func(c *Config) { c.VerifierTrustAnchorsPEM, c.VerifierCRL = "", nil },
		"no verifier crl":     func(c *Config) { c.VerifierCRL = nil },
		"pinned tls anchors":  func(c *Config) { c.VerifierTLSTrustAnchorsPEM = c.VerifierTrustAnchorsPEM },
	} {
		cfg := productionTestConfig(t)
		mutate(&cfg)
		if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
			t.Errorf("%s: loaded", name)
		}
	}
	cfg := baseTestConfig(t)
	cfg.Assurance = assuranceDevelopment
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err != nil {
		t.Errorf("development: %v", err)
	}
}

// Under production, the walletflow engine builds its own HTTP client,
// which dials public addresses only: a Verifier on loopback, as the
// fake one is, is refused before anything is fetched — why the
// production legs run on interop/prodnet.sh's network.
func TestHandleAuthorizeWalletflow_ProductionRefusesLoopback(t *testing.T) {
	srv, issuerCA := setupWalletUnderTest(t)
	_, ts, built, _ := newFakeVerifierServer(t, srv, newTestQuery(t, "urn:eudi:pid:1"), issuerCA)
	roots := srv.trust.(wallet.X5CVerifierRoots)
	roots.Revocation = certrevocation.NoCheck{}
	cfg := Config{VCT: "urn:eudi:pid:1", Engine: engineWalletflow, Assurance: assuranceProduction}
	client, verified, err := cfg.verifierHTTPClient()
	if err != nil || !verified {
		t.Fatalf("verifierHTTPClient: %v, verified %v", err, verified)
	}
	flow, err := newFlow(cfg, srv.cred, roots, client)
	if err != nil {
		t.Fatalf("newFlow under production: %v", err)
	}
	srv.flow = flow

	target := "/authorize?" + url.Values{"client_id": {built.ClientID}, "request_uri": {ts.URL + "/request/1"}}.Encode()
	rec := httptest.NewRecorder()
	srv.handleAuthorizeWalletflow(rec, httptest.NewRequest(http.MethodGet, target, nil))
	body, _ := io.ReadAll(rec.Body)
	if rec.Code == http.StatusOK || !strings.Contains(string(body), "fapihttp: target address is not allowed") {
		t.Fatalf("handleAuthorizeWalletflow: status %d: %s, want the loopback Verifier refused", rec.Code, body)
	}
}
