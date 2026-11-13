package main

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

func TestDirectPostAction(t *testing.T) {
	cases := []struct {
		name    string
		localOK bool
		body    string
		want    walletAction
	}{
		{"a non-200 is a refusal", false, "wallet: parse authorization request: signature verification failed", actionRefused},
		{"a sent error response", true, "<h1>Rejected</h1><p>Sent error response: access_denied: no match</p>", actionSentError("access_denied")},
		{"anything else presented", true, "<h1>Presented</h1>", actionPresented},
	}
	for _, c := range cases {
		if got := directPostAction(c.localOK, c.body); got != c.want {
			t.Errorf("%s: directPostAction = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDCAPIAction(t *testing.T) {
	if got := dcapiAction(dcapiAnswer{Result: []byte(`{"exception":"NotAllowedError"}`)}); got != actionRefused {
		t.Errorf("an exception = %q, want refused", got)
	}
	if got := dcapiAction(dcapiAnswer{Result: []byte(`{"data":{}}`), SentError: "access_denied"}); got != actionSentError("access_denied") {
		t.Errorf("a sent error = %q", got)
	}
	if got := dcapiAction(dcapiAnswer{Result: []byte(`{"data":{}}`)}); got != actionPresented {
		t.Errorf("a presentation = %q", got)
	}
}

// expectTyp and typRefusal are the invalid-request-object-typ
// module's expectation and the refusal it expects, as the wallet
// answers it.
var (
	expectTyp  = expectations["oid4vp-1final-wallet-negative-test-invalid-request-object-typ"]
	typRefusal = `wallet: parse authorization request: typ = "jwt", want "oauth-authz-req+jwt"`
)

func TestGrade(t *testing.T) {
	warning := []conformancesuite.LogEntry{{Result: "WARNING", Src: "SomeCondition", Msg: "hm"}}
	cases := []struct {
		name    string
		exp     expectation
		action  walletAction
		status  string
		result  string
		entries []conformancesuite.LogEntry
		wantErr bool
	}{
		{"presented as expected", expectPresent, actionPresented, "FINISHED", "PASSED", nil, false},
		{"refused as expected, left for review", expectTyp, actionRefused, "FINISHED", "REVIEW", nil, false},
		{"the expected error response", expectAccessDenied, actionSentError("access_denied"), "FINISHED", "PASSED", nil, false},
		// The W1 gap: a wallet that presents where it must refuse.
		{"presented a request it must refuse", expectTyp, actionPresented, "FINISHED", "REVIEW", nil, true},
		{"refused a request it must present", expectPresent, actionRefused, "FINISHED", "REVIEW", nil, true},
		{"another error code", expectAccessDenied, actionSentError("invalid_request"), "FINISHED", "PASSED", nil, true},
		{"a warning REVIEW hides", expectTyp, actionRefused, "FINISHED", "REVIEW", warning, true},
		{"an allowed warning", expectation{action: actionPresented, result: "WARNING", allowedWarnings: []string{"SomeCondition"}}, actionPresented, "FINISHED", "WARNING", warning, false},
		{"a WARNING result where PASSED is expected", expectPresent, actionPresented, "FINISHED", "WARNING", warning, true},
		{"interrupted", expectPresent, actionPresented, "INTERRUPTED", "PASSED", nil, true},
		{"a review where a pass is expected", expectPresent, actionPresented, "FINISHED", "REVIEW", nil, true},
	}
	for _, c := range cases {
		err := grade(c.exp, c.action, typRefusal, c.status, c.result, c.entries)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: grade = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}

// TestGrade_RefusalReason checks a refuse module passes only on a
// refusal for the reason it tests: the suite leaves any refusal for
// review.
func TestGrade_RefusalReason(t *testing.T) {
	exp := expectations["oid4vp-1final-wallet-negative-test-invalid-client-id-prefix"]
	cases := []struct {
		name, refusal string
		wantErr       bool
	}{
		{"direct_post.jwt", `wallet: parse authorization request: client_id "invalid_scheme:q5b3" does not match x5c leaf's own x509_hash "x509_hash:q5b3"`, false},
		{"dc_api.jwt, multi-signed", `NotAllowedError: wallet: parse dc api request: no signature verifies: signature 0: client_id "invalid_scheme:H" does not match x5c leaf's own x509_hash "x509_hash:H"`, false},
		{"a bad signature instead", "wallet: parse authorization request: signature verification failed: jose: ES256 signature verification failed", true},
		{"an unreachable request_uri", `wallet: fetch request object: Get "https://suite/request": connection refused`, true},
		{"nothing said", "", true},
	}
	for _, c := range cases {
		err := grade(exp, actionRefused, c.refusal, "FINISHED", "REVIEW", nil)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: grade = %v, want error %v", c.name, err, c.wantErr)
		}
	}
	if err := grade(expectation{action: actionRefused, result: "REVIEW"}, actionRefused, "anything", "FINISHED", "REVIEW", nil); err == nil {
		t.Error("a refuse expectation naming no refusal passed")
	}
}

// TestExpectations_EveryRefusalNamed checks every module the wallet
// must refuse names the refusal it expects.
func TestExpectations_EveryRefusalNamed(t *testing.T) {
	for name, exp := range expectations {
		if exp.action == actionRefused && len(exp.refusal) == 0 {
			t.Errorf("%s: no expected refusal", name)
		}
	}
}

func TestDCAPIRefusal(t *testing.T) {
	got := dcapiRefusal(dcapiAnswer{Result: []byte(`{"exception":{"name":"NotAllowedError","message":"wallet: typ"}}`)})
	if got != "NotAllowedError: wallet: typ" {
		t.Errorf("dcapiRefusal = %q", got)
	}
	if got := dcapiRefusal(dcapiAnswer{Result: []byte(`not json`)}); got != "not json" {
		t.Errorf("dcapiRefusal(not json) = %q", got)
	}
}

func TestExpectationFor_UnclassifiedModuleFails(t *testing.T) {
	if _, err := expectationFor("oid4vp-1final-wallet-some-new-module"); err == nil {
		t.Fatal("expectationFor(an unknown module) = nil error")
	}
	if exp, err := expectationFor("oid4vp-1final-wallet-negative-test-missing-request-object-typ"); err != nil || exp.action != actionRefused || exp.result != "REVIEW" {
		t.Fatalf("expectationFor(missing-request-object-typ) = %v, %v", exp, err)
	}
}
