package conformanceverifier

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

func TestGrade(t *testing.T) {
	statusWarning := []conformancesuite.LogEntry{{Result: "WARNING", Src: "EnsureVerifierFetchedRevocationList"}}
	otherWarning := []conformancesuite.LogEntry{{Result: "WARNING", Src: "ValidateRequestObjectIat"}}
	failure := []conformancesuite.LogEntry{{Result: "FAILURE", Src: "ValidateRequestObjectSignatureAgainstX5cHeader"}}
	cases := []struct {
		name            string
		exp             Expectation
		status, result  string
		verifierOutcome string
		entries         []conformancesuite.LogEntry
		wantErr         bool
	}{
		{"accepted", Accept, "FINISHED", "REVIEW", outcomeVerified, nil, false},
		{"accepted, the status list not fetched", Accept, "FINISHED", "REVIEW", outcomeVerified, statusWarning, false},
		{"refused", Refuse, "FINISHED", "PASSED", outcomeFailed, nil, false},
		// V1: a negative module the Verifier answered 200 used to pass
		// on REVIEW alone.
		{"accepted a presentation it must refuse", Refuse, "FINISHED", "REVIEW", outcomeVerified, nil, true},
		{"refused a presentation it must accept", Accept, "FINISHED", "FAILED", outcomeFailed, nil, true},
		{"a REVIEW whose result page reports a failure", Accept, "FINISHED", "REVIEW", outcomeFailed, nil, true},
		{"a refusal not reported", Refuse, "FINISHED", "PASSED", outcomeVerified, nil, true},
		{"a warning REVIEW hides", Accept, "FINISHED", "REVIEW", outcomeVerified, otherWarning, true},
		{"the status warning on a refused module", Refuse, "FINISHED", "PASSED", outcomeFailed, statusWarning, true},
		{"a logged failure", Accept, "FINISHED", "REVIEW", outcomeVerified, failure, true},
		{"interrupted", Refuse, "INTERRUPTED", "PASSED", outcomeFailed, nil, true},
		{"no expectation", 0, "FINISHED", "PASSED", outcomeFailed, nil, true},
	}
	for _, c := range cases {
		err := Grade(c.exp, c.status, c.result, c.verifierOutcome, c.entries)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Grade = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}

func TestExpectations_DrivenAndNotDrivenAreDisjoint(t *testing.T) {
	for name := range notDriven {
		if _, ok := expectations[name]; ok {
			t.Errorf("%s is both driven and not driven", name)
		}
	}
	for _, name := range []string{"oid4vp-1final-verifier-kb-jwt-iat-in-past", "oid4vp-1final-verifier-kb-jwt-iat-in-future"} {
		if expectations[name] != Refuse {
			t.Errorf("%s = %v, want Refuse (the suite's VP1FinalVerifierKbJwtIatIn* are negative modules)", name, expectations[name])
		}
	}
}

func TestSessionIDOf(t *testing.T) {
	id, err := sessionIDOf("?client_id=x509_hash%3Aabc&request_uri=https%3A%2F%2Fconformance-verifier%3A8443%2Frequest%2Fs3ss10n&request_uri_method=post")
	if err != nil || id != "s3ss10n" {
		t.Fatalf("sessionIDOf = %q, %v; want s3ss10n", id, err)
	}
	if _, err := sessionIDOf("?client_id=x&request_uri=https%3A%2F%2Fhost%2Fother%2Fid"); err == nil {
		t.Fatal("sessionIDOf(a request_uri off /request/) = nil error")
	}
}

func TestModuleResultLine(t *testing.T) {
	line := ModuleResult{TestName: "m", Expected: Refuse, Status: "FINISHED", Result: "REVIEW", VerifierOutcome: outcomeVerified}.line()
	if !strings.Contains(line, "FINISHED=REVIEW verifier=verified (want refuse") {
		t.Fatalf("line = %q", line)
	}
}
