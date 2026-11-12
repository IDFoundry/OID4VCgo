package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// The walletflow engine answers a real Verifier's request end to end,
// as TestHandleAuthorize_FullRoundTripAgainstARealVerifier does the
// default engine: walletflow fetches and verifies the Request Object,
// presents the fixture credential from its store, signed by the
// configured holder key, and the Verifier verifies the response.
func TestHandleAuthorizeWalletflow_FullRoundTripAgainstARealVerifier(t *testing.T) {
	srv, issuerCA := setupWalletUnderTest(t)
	_, ts, built, got := newFakeVerifierServer(t, srv, newTestQuery(t, "urn:eudi:pid:1"), issuerCA)
	srv.http = ts.Client()
	flow, err := newFlow(Config{VCT: "urn:eudi:pid:1"}, srv.cred, srv.trust, srv.http)
	if err != nil {
		t.Fatal(err)
	}
	srv.flow = flow

	target := "/authorize?" + url.Values{"client_id": {built.ClientID}, "request_uri": {ts.URL + "/request/1"}}.Encode()
	rec := httptest.NewRecorder()
	srv.handleAuthorizeWalletflow(rec, httptest.NewRequest(http.MethodGet, target, nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Presented") {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("handleAuthorizeWalletflow: status %d: %s", rec.Code, body)
	}
	if got.err != nil {
		t.Fatalf("verifier's own VerifyResponse: %v", got.err)
	}
	if got.claims["given_name"] != "Jean" || got.claims["family_name"] != "Dupont" {
		t.Fatalf("disclosed claims = %+v, want given_name=Jean family_name=Dupont", got.claims)
	}
}

func TestLoadConfig_Engine(t *testing.T) {
	for engine, ok := range map[string]bool{"": true, "wallet": true, "walletflow": true, "other": false} {
		cfg := baseTestConfig(t)
		cfg.Engine = engine
		if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); (err == nil) != ok {
			t.Errorf("engine %q: %v", engine, err)
		}
	}
}

// verifyVerifierTLS trusts a server presenting an anchor itself for any
// host name, and otherwise a chain to an anchor for the name dialed.
func TestVerifyVerifierTLS(t *testing.T) {
	ca, caKey := testcert.CA(t, "tls-ca")
	leaf, _ := testcert.Issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "verifier.example"}, DNSNames: []string{"verifier.example"}}, ca, caKey)
	other, _ := testcert.CA(t, "other-ca")
	state := func(name string, chain ...*x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{ServerName: name, PeerCertificates: chain}
	}
	for _, c := range []struct {
		name    string
		anchors []*x509.Certificate
		state   tls.ConnectionState
		ok      bool
	}{
		{"pinned, under any name", []*x509.Certificate{leaf}, state("localhost.emobix.co.uk", leaf), true},
		{"a chain to the anchor, for its name", []*x509.Certificate{ca}, state("verifier.example", leaf, ca), true},
		{"a chain to the anchor, for another name", []*x509.Certificate{ca}, state("elsewhere.example", leaf, ca), false},
		{"a chain to another anchor", []*x509.Certificate{other}, state("verifier.example", leaf, ca), false},
		{"no certificate", []*x509.Certificate{ca}, state("verifier.example"), false},
	} {
		if err := verifyVerifierTLS(c.anchors, c.state); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// With anchors, the client refuses a server whose certificate isn't
// one of them, and accepts one that is.
func TestVerifierHTTPClient(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(ts.Close)
	pinned := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}))
	other, _ := testcert.CA(t, "other-ca")
	unrelated := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: other.Raw}))
	for anchors, ok := range map[string]bool{pinned: true, unrelated: false} {
		client, verified, err := (Config{VerifierTLSTrustAnchorsPEM: anchors}).verifierHTTPClient()
		if err != nil || !verified {
			t.Fatalf("verifierHTTPClient: verified %v, %v", verified, err)
		}
		res, err := client.Get(ts.URL) //nolint:noctx // a test server
		if err == nil {
			_ = res.Body.Close()
		}
		if (err == nil) != ok {
			t.Errorf("pinned %v: %v", ok, err)
		}
	}
	if _, _, err := (Config{VerifierTLSTrustAnchorsPEM: "not a certificate"}).verifierHTTPClient(); err == nil {
		t.Error("anchors with no certificate were accepted")
	}
}
