package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// suiteTestConfig is the status configuration the OIDF suite runs
// write (internal/conformanceverifier's configureTrust): the TLS
// certificate pinned, private addresses allowed, a status reference
// optional.
func suiteTestConfig(t *testing.T) Config {
	t.Helper()
	caPEM, _ := testPEMCertAndKey(t)
	pinPEM, _ := testPEMCertAndKey(t)
	cfg := baseTestConfig(t)
	cfg.CredentialIssuerJWK = nil
	cfg.CredentialIssuerTrustAnchorsPEM = caPEM
	cfg.StatusListTrustAnchorsPEM = caPEM
	cfg.StatusListTLSPinnedCertificatePEM = pinPEM
	cfg.StatusListAllowPrivate = true
	cfg.StatusReferenceOptional = true
	return cfg
}

func TestLoadConfig_SuiteStatusRoundTrips(t *testing.T) {
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, suiteTestConfig(t)))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.StatusListTLSPinnedCertificatePEM == "" || !got.StatusListAllowPrivate || !got.StatusReferenceOptional {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_SuiteStatusOptionsNeedTrustAnchors(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"status_list_tls_pinned_certificate_pem": func(c *Config) { c.StatusListAllowPrivate, c.StatusReferenceOptional = false, false },
		"status_list_allow_private":              func(c *Config) { c.StatusListTLSPinnedCertificatePEM, c.StatusReferenceOptional = "", false },
		"status_reference_optional":              func(c *Config) { c.StatusListTLSPinnedCertificatePEM, c.StatusListAllowPrivate = "", false },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := suiteTestConfig(t)
			cfg.StatusListTrustAnchorsPEM = ""
			mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want one for %s without status_list_trust_anchors_pem", name)
			}
		})
	}
}

func TestLoadConfig_OneStatusListTLSTrust(t *testing.T) {
	cfg := suiteTestConfig(t)
	cfg.StatusListTLSTrustAnchorsPEM = cfg.StatusListTrustAnchorsPEM
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
		t.Fatal("loadConfig = nil error, want one for both status_list_tls_trust_anchors_pem and status_list_tls_pinned_certificate_pem")
	}
}

func TestConfig_StatusPolicyForTheSuite(t *testing.T) {
	p, err := suiteTestConfig(t).statusPolicy()
	if err != nil {
		t.Fatalf("statusPolicy: %v", err)
	}
	if p.RequireReference || !p.Checker.Fetcher.AllowPrivate || p.Checker.Fetcher.AllowLoopback || p.Checker.Fetcher.HTTP == nil {
		t.Fatalf("statusPolicy = %+v, want no RequireReference, AllowPrivate alone and an HTTP client", p)
	}
	for name, cfg := range map[string]Config{"suite": suiteTestConfig(t), "interop": interopTestConfig(t)} {
		p, err := cfg.statusPolicy()
		if err != nil {
			t.Fatalf("%s: statusPolicy: %v", name, err)
		}
		if _, ok := p.Checker.Options.Revocation.(certrevocation.NoCheck); !ok || p.Checker.Cache == nil {
			t.Fatalf("%s: statusPolicy = %+v, want a Cache and an explicit NoCheck revocation decision", name, p)
		}
	}
	bad := suiteTestConfig(t)
	bad.StatusListTLSPinnedCertificatePEM = "not a certificate"
	if _, err := bad.statusPolicy(); err == nil || !strings.Contains(err.Error(), "status_list_tls_pinned_certificate_pem") {
		t.Fatalf("statusPolicy error = %v, want one naming status_list_tls_pinned_certificate_pem", err)
	}
}

func TestPinnedTLSConfig(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	other, err := conformancecert.ParseCertificatePEM(suiteTestConfig(t).StatusListTLSPinnedCertificatePEM)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	for name, c := range map[string]struct {
		pin    *x509.Certificate
		wantOK bool
	}{
		"the pinned certificate": {srv.Certificate(), true},
		"another certificate":    {other, false},
	} {
		t.Run(name, func(t *testing.T) {
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: pinnedTLSConfig(c.pin)}}
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
			}
			if (err == nil) != c.wantOK {
				t.Fatalf("GET with %s pinned: %v, want success %v", name, err, c.wantOK)
			}
		})
	}
}

func TestConfig_StatusPolicyPinsFromPEM(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	cfg := suiteTestConfig(t)
	cfg.StatusListTLSPinnedCertificatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	p, err := cfg.statusPolicy()
	if err != nil {
		t.Fatalf("statusPolicy: %v", err)
	}
	resp, err := p.Checker.Fetcher.HTTP.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET through the status list client: %v", err)
	}
	_ = resp.Body.Close()
}
