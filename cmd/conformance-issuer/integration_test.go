package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestNewServerMux_ServesRealMetadataAndJWKS is the same scenario this
// binary was manually smoke-tested with (see README.md's own
// "Status"): newServerMux wires a real fapigo/server.Server and a real
// oid4vcigo/issuer.Issuer together, and both the FAPI 2.0 Authorization
// Server metadata and the OID4VCI Credential Issuer metadata come back
// correctly formed from the exact same production wiring main.go uses
// — not a mock of either role.
func TestNewServerMux_ServesRealMetadataAndJWKS(t *testing.T) {
	cfg := baseTestConfig(t)

	ts := httptest.NewUnstartedServer(nil)
	cfg.Issuer = "https://" + ts.Listener.Addr().String()

	mux, err := newServerMux(cfg)
	if err != nil {
		t.Fatalf("newServerMux: %v", err)
	}
	ts.Config.Handler = mux
	tlsCert, err := cfg.tlsCertificate()
	if err != nil {
		t.Fatalf("tlsCertificate: %v", err)
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	ts.StartTLS()
	defer ts.Close()

	// This binary's own generated cert (conformancecert.SelfSignedPEM)
	// replaced httptest's own auto-generated one above, so ts.Client()'s
	// matching trust root no longer applies — skip verification instead,
	// the same choice cmd/conformance-wallet-vp's own outbound client
	// makes for exactly this reason (see its own doc comment).
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // test-only, see comment above

	t.Run("authorization server metadata", func(t *testing.T) {
		body := getJSON(t, client, ts.URL+"/.well-known/openid-configuration")
		if body["issuer"] != cfg.Issuer {
			t.Fatalf("issuer = %v, want %v", body["issuer"], cfg.Issuer)
		}
		if body["pushed_authorization_request_endpoint"] == nil {
			t.Fatalf("missing pushed_authorization_request_endpoint: %+v", body)
		}
		methods, _ := body["token_endpoint_auth_methods_supported"].([]any)
		if !containsAny(methods, "attest_jwt_client_auth") {
			t.Fatalf("token_endpoint_auth_methods_supported = %v, want attest_jwt_client_auth present", methods)
		}
	})

	t.Run("oauth-authorization-server metadata mirrors openid-configuration", func(t *testing.T) {
		body := getJSON(t, client, ts.URL+"/.well-known/oauth-authorization-server")
		if body["issuer"] != cfg.Issuer {
			t.Fatalf("issuer = %v, want %v", body["issuer"], cfg.Issuer)
		}
		if body["pushed_authorization_request_endpoint"] == nil {
			t.Fatalf("missing pushed_authorization_request_endpoint: %+v", body)
		}
	})

	t.Run("credential issuer metadata", func(t *testing.T) {
		body := getJSON(t, client, ts.URL+"/.well-known/openid-credential-issuer")
		if body["credential_issuer"] != cfg.Issuer {
			t.Fatalf("credential_issuer = %v, want %v", body["credential_issuer"], cfg.Issuer)
		}
		configs, _ := body["credential_configurations_supported"].(map[string]any)
		cc, ok := configs[cfg.CredentialConfigurationID].(map[string]any)
		if !ok {
			t.Fatalf("credential_configurations_supported missing %q: %+v", cfg.CredentialConfigurationID, body)
		}
		if cc["vct"] != cfg.VCT {
			t.Fatalf("vct = %v, want %v", cc["vct"], cfg.VCT)
		}
	})

	t.Run("jwks", func(t *testing.T) {
		body := getJSON(t, client, ts.URL+"/jwks")
		keysArr, _ := body["keys"].([]any)
		if len(keysArr) == 0 {
			t.Fatalf("jwks has no keys: %+v", body)
		}
	})
}

func getJSON(t *testing.T, client *http.Client, url string) map[string]any {
	t.Helper()
	resp, err := client.Get(url) //nolint:gosec,noctx // url is a fixed httptest.Server URL built in this same test, not attacker-controlled
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: status %d: %s", url, resp.StatusCode, raw)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal body: %v (%s)", err, raw)
	}
	return body
}

func containsAny(list []any, want string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
