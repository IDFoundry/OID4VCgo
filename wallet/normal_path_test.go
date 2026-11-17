package wallet_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// nonNormalPaths are endpoint URLs whose request-target and normalized
// htu name different paths (RFC 3986 §6.2.2), which a front end routing
// by the raw path and a server comparing the normalized htu would read
// as different resources.
var nonNormalPaths = map[string]string{
	"encoded dot segment":     "https://issuer.example/tenant-a/%2e%2e/tenant-b/credential",
	"uppercase encoded dots":  "https://issuer.example/tenant-a/%2E%2E/tenant-b/credential",
	"half-encoded dot":        "https://issuer.example/tenant-a/.%2e/tenant-b/credential",
	"single encoded dot":      "https://issuer.example/a/%2e/credential",
	"encoded unreserved char": "https://issuer.example/cred%65ntial",
	"encoded tilde":           "https://issuer.example/%7Euser/credential",
	"dot-dot segment":         "https://issuer.example/tenant-a/../tenant-b/credential",
	"trailing dot segment":    "https://issuer.example/credential/.",
}

// The wallet's DPoP clients refuse, before sending anything, an endpoint
// whose path isn't in normal form, as fapigo/client's does: a DPoP
// proof's htu can't name it unambiguously. A normal path, a lowercase
// percent-encoding of a reserved character among them, is sent.
func TestDPoPClients_RefuseNonNormalPaths(t *testing.T) {
	sent := 0
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		sent++
		return jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP"}`)), nil
	})
	key := testP256Key(t)
	resource := w.DPoPResourceClient(fapi.NewSecret("access-token"), key)
	for name, raw := range nonNormalPaths {
		endpoint, err := fapi.ParseEndpointURL(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, raw, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := resource.Do(context.Background(), req); err == nil || !strings.Contains(err.Error(), "dot segments") {
			t.Errorf("%s: resource request: %v, want it refused", name, err)
		}
		if _, err := w.RequestPreAuthorizedCodeToken(context.Background(), endpoint, wallet.PreAuthorizedCodeTokenRequest{
			PreAuthorizedCode: "abc123", DPoPKey: key,
		}); err == nil || !strings.Contains(err.Error(), "dot segments") {
			t.Errorf("%s: token request: %v, want it refused", name, err)
		}
	}
	if sent != 0 {
		t.Fatalf("%d requests sent to non-normal paths", sent)
	}

	const normal = "https://issuer.example/tenant%2fa/credential"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, normal, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	res, err := resource.Do(context.Background(), req)
	if err != nil {
		t.Fatalf("normal path: %v", err)
	}
	_ = res.Body.Close()
	endpoint, err := fapi.ParseEndpointURL(normal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RequestPreAuthorizedCodeToken(context.Background(), endpoint, wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123", DPoPKey: key,
	}); err != nil {
		t.Fatalf("normal token endpoint: %v", err)
	}
	if sent != 2 {
		t.Errorf("sent %d requests to the normal path, want 2", sent)
	}
}

// GenerateDPoPProof, exported for a caller's own sender-constrained
// requests, refuses an htu whose path isn't in normal form, as the
// wallet's own DPoP clients refuse such an endpoint.
func TestGenerateDPoPProof_RefusesNonNormalPaths(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("GenerateDPoPProof sent a request")
		return nil, nil
	})
	key := testP256Key(t)
	for name, raw := range nonNormalPaths {
		if _, err := w.GenerateDPoPProof(key, http.MethodPost, raw, "", ""); err == nil || !strings.Contains(err.Error(), "dot segments") {
			t.Errorf("%s: %v, want it refused", name, err)
		}
	}
	if _, err := w.GenerateDPoPProof(key, http.MethodPost, "https://issuer.example/tenant%2fa/credential", "", ""); err != nil {
		t.Errorf("normal path: %v", err)
	}
}
