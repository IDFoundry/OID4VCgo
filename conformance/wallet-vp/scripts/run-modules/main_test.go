package main

import "testing"

func TestExtractSentErrorCode(t *testing.T) {
	body := `<html><body><h1>Rejected</h1><p>Sent error response: access_denied: wallet: present credentials: wallet: match dcql query: credential set: no option is satisfied: credential query "nonexistent_credential": no held credential satisfies this credential query</p></body></html>`
	code, ok := extractSentErrorCode(body)
	if !ok {
		t.Fatal("extractSentErrorCode: ok = false, want true")
	}
	if code != "access_denied" {
		t.Errorf("code = %q, want %q", code, "access_denied")
	}
}

func TestExtractSentErrorCode_NoMatch(t *testing.T) {
	body := `<html><body><h1>Presented</h1><p>Followed redirect_uri: https://example.com/callback</p></body></html>`
	if _, ok := extractSentErrorCode(body); ok {
		t.Error("extractSentErrorCode: ok = true, want false for a body with no sent-error-response line")
	}
}

func TestExtractSentErrorCode_LocalRejection(t *testing.T) {
	// A local rejection (no response_uri contact at all) has no "Sent
	// error response" line — just the raw Go error text.
	body := `wallet: parse authorization request: signature verification failed: jose: ES256 signature verification failed`
	if _, ok := extractSentErrorCode(body); ok {
		t.Error("extractSentErrorCode: ok = true, want false for a local-rejection body")
	}
}

func TestAllMandatoryClaimsCredentialType(t *testing.T) {
	cases := map[string]string{
		"sd_jwt_vc": "eudi_pid",
		"":          "eudi_pid",
		"iso_mdl":   "mdl",
	}
	for format, want := range cases {
		if got := allMandatoryClaimsCredentialType(format); got != want {
			t.Errorf("allMandatoryClaimsCredentialType(%q) = %q, want %q", format, got, want)
		}
	}
}
