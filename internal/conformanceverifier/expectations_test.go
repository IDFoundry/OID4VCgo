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
	// A refusal the page reports, as cmd/conformance-verifier writes
	// it, for the kb-jwt-signature module's expected refusal.
	const kbSignature = "oid4vp-1final-verifier-invalid-kb-jwt-signature"
	const kbSignatureRefusal = "reason: holder_binding\nverifier: verify response: credential query \"cred1\": verifier: verify: sdjwtvc: key binding JWT: sdjwtvc: verify key binding JWT signature: jose: ES256 signature verification failed"
	cases := []struct {
		name            string
		exp             Expectation
		status, result  string
		verifierOutcome string
		entries         []conformancesuite.LogEntry
		wantErr         bool
	}{
		{"accepted", Accept, "FINISHED", "REVIEW", outcomeVerified, nil, false},
		{"accepted, the status list not fetched", Accept, "FINISHED", "REVIEW", outcomeVerified, statusWarning, true},
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
		{"skipped", Skip, "FINISHED", "SKIPPED", outcomePending, nil, false},
		{"run where it must be skipped", Skip, "FINISHED", "REVIEW", outcomeVerified, nil, true},
		{"skipped, yet answered", Skip, "FINISHED", "SKIPPED", outcomeVerified, nil, true},
	}
	for _, c := range cases {
		err := Grade(c.exp, refusals[kbSignature], c.status, c.result, c.verifierOutcome, kbSignatureRefusal, c.entries)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Grade = %v, want error %v", c.name, err, c.wantErr)
		}
	}
}

// TestGrade_RefusalReason checks a Refuse module passes only on a
// refusal for the reason it tests: the suite grades any refusal
// PASSED.
func TestGrade_RefusalReason(t *testing.T) {
	const name = "oid4vp-1final-verifier-invalid-kb-jwt-nonce"
	want := refusals[name]
	cases := []struct {
		name, refusal string
		wantErr       bool
	}{
		{"the nonce", "the answer was refused: a credential's holder binding failed (holder_binding)\nreason: holder_binding\nverifier: verify response: credential query \"cred1\": verifier: verify: a presentation isn't bound to this request: sdjwtvc: key binding JWT: sdjwtvc: key binding JWT is for another request: its nonce does not match the expected value", false},
		{"another holder binding check", "reason: holder_binding\nverifier: verify response: sdjwtvc: key binding JWT is too old", true},
		{"another reason", "reason: untrusted_issuer\nverifier: verify response: x5c: certificate signed by unknown authority", true},
		{"no reason shown", "", true},
	}
	for _, c := range cases {
		err := Grade(Refuse, want, "FINISHED", "PASSED", outcomeFailed, c.refusal, nil)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: Grade = %v, want error %v", c.name, err, c.wantErr)
		}
	}
	if err := Grade(Refuse, nil, "FINISHED", "PASSED", outcomeFailed, "reason: holder_binding", nil); err == nil {
		t.Error("a Refuse module with no expected refusal passed")
	}
}

// TestRefusals_EveryRefuseModule checks every Refuse module names its
// expected refusal, and only those do.
func TestRefusals_EveryRefuseModule(t *testing.T) {
	for name, e := range expectations {
		if _, ok := refusals[name]; ok != (e == Refuse) {
			t.Errorf("%s: %v, refusal classified %v", name, e, ok)
		}
	}
	for name, want := range refusals {
		if len(want) == 0 {
			t.Errorf("%s: no expected refusal text", name)
		}
	}
}

func TestPreText(t *testing.T) {
	page := "<html><body><h1>Verification failed</h1><pre>reason: holder_binding</pre><pre>a &#34;quoted&#34; &lt;error&gt;</pre></body></html>"
	if got, want := preText(page), "reason: holder_binding\na \"quoted\" <error>"; got != want {
		t.Errorf("preText = %q, want %q", got, want)
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
	for _, name := range []string{"oid4vp-1final-verifier-present-revoked-credential", "oid4vp-1final-verifier-present-credential-on-identifier-list"} {
		if expectations[name] != Refuse {
			t.Errorf("%s = %v, want Refuse", name, expectations[name])
		}
	}
}

func TestExpectationFor(t *testing.T) {
	// Run under either engine: the transactions engine's requests ask
	// for request_uri_method=post (TransactionsConfig.RequestURIMethodPost).
	const post = "oid4vp-1final-verifier-request-uri-method-post"
	if e, ok := expectationFor(post); !ok || e != Accept {
		t.Errorf("%s = %v, %v; want Accept", post, e, ok)
	}
	if _, ok := expectationFor("oid4vp-1final-verifier-unknown"); ok {
		t.Error("an unknown module has an expectation")
	}
	if Skip.String() == "no expectation" {
		t.Error("Skip has no description")
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
	line = ModuleResult{TestName: "m", Expected: Refuse, Status: "FINISHED", Result: "PASSED", VerifierOutcome: outcomeFailed, VerifierRefusal: "reason: x"}.line()
	if !strings.Contains(line, `refusal "reason: x"`) {
		t.Fatalf("line = %q", line)
	}
}
