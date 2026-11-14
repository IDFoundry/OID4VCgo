package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// TestIssuerPKI checks the issuer's config publishes and checks all
// three CAs' CRLs, the attester's leaves name the attester, and the
// controls name their error responses.
func TestIssuerPKI(t *testing.T) {
	attester, _ := url.Parse(attesterIssuer)
	p, err := newIssuerPKI("https://conformance-issuer:8443", attester)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.publisher.CRLs) != 3 || len(p.trust.DistributionPoints) != 3 {
		t.Errorf("%d CRLs published, %d distribution points; want 3 each", len(p.publisher.CRLs), len(p.trust.DistributionPoints))
	}
	if _, err := p.publisher.Handler(); err != nil {
		t.Errorf("crl_publisher: %v", err)
	}
	for _, c := range p.controls() {
		leaf := parsePEMCert(t, c.attester.leafPEM)
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != attesterIssuer || c.code == "" || c.description == "" {
			t.Errorf("%s: URIs %v, %s %q", controlKey(c), leaf.URIs, c.code, c.description)
		}
	}
	if _, err := newIssuerPKI("not a url", attester); err == nil {
		t.Error("an issuer base URL with no host was accepted")
	}
}

func TestLoggedErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/log/m1" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`[{"msg":"x"},{"error":"invalid_client","error_description":"attester certificate is revoked"}]`))
	}))
	defer srv.Close()
	got, err := loggedErrorResponse(srv.Client(), srv.URL+"/", "m1", "invalid_client", "attester certificate is revoked")
	if err != nil || !got {
		t.Errorf("logged response: %v, %v; want found", got, err)
	}
	if got, err := loggedErrorResponse(srv.Client(), srv.URL+"/", "m1", "server_error", "attester certificate is revoked"); err != nil || got {
		t.Errorf("another code: %v, %v; want not found", got, err)
	}
}

func TestControlHelpers(t *testing.T) {
	if id := moduleIDOf("INTERRUPTED=FAILED" + moduleSuffix("https://suite/", "abc")); id != "abc" {
		t.Errorf("moduleIDOf = %q, want abc", id)
	}
	if id := moduleIDOf("no module"); id != "" {
		t.Errorf("moduleIDOf = %q, want none", id)
	}
	plain := map[string]string{"vci_credential_encryption": "plain"}
	runs := []batteryRun{
		{module: conformancesuite.PlanModule{TestModule: happyFlowTestName, Variant: map[string]string{"vci_credential_encryption": "encrypted"}}},
		{module: conformancesuite.PlanModule{TestModule: happyFlowTestName, Variant: plain}},
	}
	if got := happyFlowVariant(runs); got["vci_credential_encryption"] != "plain" {
		t.Errorf("happyFlowVariant = %v, want the plain one", got)
	}
	if got := happyFlowVariant(runs[:1]); got != nil {
		t.Errorf("happyFlowVariant = %v, want none", got)
	}
}

func TestRefusedAtPAR(t *testing.T) {
	suffix := moduleSuffix("https://suite/", "m")
	offerRefused := "ERROR: submit credential offer: " + parRefusedOffer + `{"cause":"CheckPAREndpointResponse201WithNoError: ..."}` + suffix
	for _, c := range []struct {
		outcome         string
		issuerInitiated bool
		want            bool
	}{
		{"FINISHED=FAILED" + suffix, false, true},
		{"INTERRUPTED=FAILED" + suffix, false, true},
		{offerRefused, true, true},
		{offerRefused, false, false},
		{"FINISHED=PASSED" + suffix, false, false},
		{"ERROR: submit credential offer: wait for WAITING", true, false},
	} {
		if got := refusedAtPAR(c.outcome, c.issuerInitiated); got != c.want {
			t.Errorf("refusedAtPAR(%q, %v) = %v, want %v", c.outcome, c.issuerInitiated, got, c.want)
		}
	}
	if id := moduleIDOf(offerRefused); id != "m" {
		t.Errorf("moduleIDOf = %q, want m", id)
	}
}
