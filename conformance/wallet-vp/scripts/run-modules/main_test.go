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

func TestUnexpectedLocalOK(t *testing.T) {
	cases := []struct {
		name                            string
		negativeTest, localOK, sendsErr bool
		want                            bool
	}{
		{"positive test with localOK is never suspicious", false, true, false, false},
		{"negative test with non-200 is never suspicious", true, false, false, false},
		{"negative test with localOK and no error response is suspicious", true, true, false, true},
		{"negative test with localOK but sends an error response is expected", true, true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := unexpectedLocalOK(c.negativeTest, c.localOK, c.sendsErr); got != c.want {
				t.Errorf("unexpectedLocalOK(%v, %v, %v) = %v, want %v", c.negativeTest, c.localOK, c.sendsErr, got, c.want)
			}
		})
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

func TestModuleResultExpected(t *testing.T) {
	cases := []struct {
		name string
		res  moduleResult
		want bool
	}{
		{"positive PASSED with localOK", moduleResult{localOK: true, result: "PASSED"}, true},
		{"positive REVIEW with localOK", moduleResult{localOK: true, result: "REVIEW"}, true},
		{"positive FAILURE with localOK is unexpected", moduleResult{localOK: true, result: "FAILURE"}, false},
		{"negative REVIEW without localOK", moduleResult{localOK: false, result: "REVIEW"}, true},
		{"negative FAILURE without localOK is unexpected", moduleResult{localOK: false, result: "FAILURE"}, false},
		{"any error is unexpected regardless of result", moduleResult{localOK: true, result: "PASSED", err: errBoom}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := moduleResultExpected(c.res); got != c.want {
				t.Errorf("moduleResultExpected(%+v) = %v, want %v", c.res, got, c.want)
			}
		})
	}
}

var errBoom = errTestBoom("boom")

type errTestBoom string

func (e errTestBoom) Error() string { return string(e) }
