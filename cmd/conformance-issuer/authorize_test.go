package main

import (
	"net/http"
	"testing"
)

// TestAuthorize_RefusesRepeatedParameters: the authorization endpoint
// refuses a repeated client_id or request_uri (RFC 6749 §3.1) with a
// local 400, as FAPIgo's own conformance AS does, rather than taking the
// first.
func TestAuthorize_RefusesRepeatedParameters(t *testing.T) {
	httpClient, cfg, _, _ := setupFullFlowTest(t, "repeated-params-client", "repeated-params-subject")
	for _, query := range []string{"client_id=a&client_id=b&request_uri=x", "client_id=a&request_uri=x&request_uri=y"} {
		resp, err := httpClient.Get(cfg.Issuer + "/authorize?" + query)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", query, resp.StatusCode)
		}
	}
}
