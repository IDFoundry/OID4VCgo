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
		{"refused as expected, left for review", expectRefuse, actionRefused, "FINISHED", "REVIEW", nil, false},
		{"the expected error response", expectAccessDenied, actionSentError("access_denied"), "FINISHED", "PASSED", nil, false},
		// The W1 gap: a wallet that presents where it must refuse.
		{"presented a request it must refuse", expectRefuse, actionPresented, "FINISHED", "REVIEW", nil, true},
		{"refused a request it must present", expectPresent, actionRefused, "FINISHED", "REVIEW", nil, true},
		{"another error code", expectAccessDenied, actionSentError("invalid_request"), "FINISHED", "PASSED", nil, true},
		{"a warning REVIEW hides", expectRefuse, actionRefused, "FINISHED", "REVIEW", warning, true},
		{"an allowed warning", expectation{action: actionPresented, result: "WARNING", allowedWarnings: []string{"SomeCondition"}}, actionPresented, "FINISHED", "WARNING", warning, false},
		{"a WARNING result where PASSED is expected", expectPresent, actionPresented, "FINISHED", "WARNING", warning, true},
		{"interrupted", expectPresent, actionPresented, "INTERRUPTED", "PASSED", nil, true},
		{"a review where a pass is expected", expectPresent, actionPresented, "FINISHED", "REVIEW", nil, true},
	}
	for _, c := range cases {
		err := grade(c.exp, c.action, c.status, c.result, c.entries)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: grade = %v, want error %v", c.name, err, c.wantErr)
		}
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
