package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestNewServerMux_ServesRealMetadataAndJWKS is the same scenario this
// binary was manually smoke-tested with (see README.md's own
// "Status"): newServerMux wires a real fapigo/server.Server and a real
// oid4vcgo/issuer.Issuer together, and both the FAPI 2.0 Authorization
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
		batch, ok := body["batch_credential_issuance"].(map[string]any)
		if !ok {
			t.Fatalf("missing batch_credential_issuance: %+v", body)
		}
		if batch["batch_size"] != float64(conformanceBatchSize) {
			t.Fatalf("batch_size = %v, want %d", batch["batch_size"], conformanceBatchSize)
		}

		reqEnc, ok := body["credential_request_encryption"].(map[string]any)
		if !ok {
			t.Fatalf("missing credential_request_encryption: %+v", body)
		}
		assertEncValuesSupported(t, "credential_request_encryption", reqEnc)
		// jwks MUST be a JSON Web Key Set (RFC 7517 §5, "{keys: [...]}"),
		// per §12.2.4's own "A JSON Web Key Set, as defined in
		// [RFC7591]" — not a bare array. Confirmed live: an earlier
		// version of issuer.Metadata() serialized this as a bare array,
		// and the OIDF suite's own VCICheckCredentialRequestEncryptionSupported
		// check correctly rejected it.
		jwks, ok := reqEnc["jwks"].(map[string]any)
		if !ok {
			t.Fatalf("credential_request_encryption.jwks = %T, want a JSON object with a \"keys\" member: %+v", reqEnc["jwks"], reqEnc)
		}
		keys, _ := jwks["keys"].([]any)
		if len(keys) != 1 {
			t.Fatalf("credential_request_encryption.jwks.keys has %d entries, want 1: %+v", len(keys), jwks)
		}
		jwk, _ := keys[0].(map[string]any)
		if jwk["kid"] != credentialRequestDecryptionKeyID {
			t.Fatalf("credential_request_encryption.jwks.keys[0].kid = %v, want %q", jwk["kid"], credentialRequestDecryptionKeyID)
		}
		// §10's own "The alg parameter MUST be present" — confirmed
		// live that the OIDF suite's own VCICheckCredentialRequestEncryptionSupported
		// check rejects a published key with no "alg" member.
		if jwk["alg"] != "ECDH-ES" {
			t.Fatalf("credential_request_encryption.jwks.keys[0].alg = %v, want %q", jwk["alg"], "ECDH-ES")
		}

		respEnc, ok := body["credential_response_encryption"].(map[string]any)
		if !ok {
			t.Fatalf("missing credential_response_encryption: %+v", body)
		}
		assertEncValuesSupported(t, "credential_response_encryption", respEnc)
	})

	t.Run("signed credential issuer metadata", func(t *testing.T) {
		unsigned := getJSON(t, client, ts.URL+"/.well-known/openid-credential-issuer")

		req, err := http.NewRequest(http.MethodGet, ts.URL+"/.well-known/openid-credential-issuer", nil) //nolint:noctx // test-only, fixed httptest.Server URL
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Accept", "application/jwt")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d: %s", resp.StatusCode, raw)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "application/jwt" {
			t.Fatalf("Content-Type = %q, want application/jwt", ct)
		}

		cert, err := cfg.credentialIssuerCertificate()
		if err != nil {
			t.Fatalf("credentialIssuerCertificate: %v", err)
		}
		header, payload, err := jose.Verify(jose.ES256, cert.PublicKey, string(raw))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if header["typ"] != issuer.MetadataJWSTyp {
			t.Fatalf("typ = %v, want %q", header["typ"], issuer.MetadataJWSTyp)
		}
		if _, ok := header["x5c"]; !ok {
			t.Fatalf("missing x5c header")
		}
		var claims map[string]any
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("unmarshal payload: %v", err)
		}
		if claims["sub"] != cfg.Issuer {
			t.Fatalf("sub = %v, want %v", claims["sub"], cfg.Issuer)
		}
		if _, ok := claims["iat"]; !ok {
			t.Fatalf("missing iat claim")
		}
		for k, v := range unsigned {
			if !reflect.DeepEqual(claims[k], v) {
				t.Fatalf("signed claim %q = %#v, want %#v (from the unsigned response)", k, claims[k], v)
			}
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

// assertEncValuesSupported checks one §10 encryption metadata object
// (credential_request_encryption or credential_response_encryption)
// advertises exactly the enc values this binary's own wiring.go
// configures (credentialEncValuesSupported) — A128GCM/A256GCM, not
// A192GCM (internal/jwe implements it, but this binary deliberately
// doesn't advertise or accept it, so "unsupported" is a real condition
// to test against).
func assertEncValuesSupported(t *testing.T, field string, obj map[string]any) {
	t.Helper()
	encValues, _ := obj["enc_values_supported"].([]any)
	if !containsAny(encValues, "A128GCM") || !containsAny(encValues, "A256GCM") {
		t.Fatalf("%s.enc_values_supported = %v, want A128GCM and A256GCM present", field, encValues)
	}
	if containsAny(encValues, "A192GCM") {
		t.Fatalf("%s.enc_values_supported = %v, want A192GCM absent (this binary doesn't support it)", field, encValues)
	}
}
