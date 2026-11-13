package conformanceverifier

import (
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// Expectation is what a module of oid4vp-1final-verifier-haip-test-plan
// expects the Verifier to do with the presentation the suite (playing
// Wallet) sends it.
type Expectation int

const (
	// Accept: the Verifier must verify the presentation. It answers
	// 200, the suite asks for a screenshot of the result page and
	// grades the module REVIEW once DriveModule fills it, and the
	// result page reports the presentation verified. REVIEW is the
	// only verdict the suite gives a Verifier that accepted a
	// presentation: whether it verified it can't be seen over HTTP.
	Accept Expectation = iota + 1
	// Refuse: the Verifier must refuse the presentation. With
	// reject_unverified_responses it answers 400, which the suite
	// grades PASSED itself, with no screenshot, and the result page
	// reports the failure.
	Refuse
	// Skip: the suite skips the module, the Verifier's request lacking
	// what it tests, so no presentation reaches the Verifier: SKIPPED,
	// with the result page still pending.
	Skip
)

func (e Expectation) String() string {
	switch e {
	case Accept:
		return "accept: FINISHED=REVIEW, verified"
	case Refuse:
		return "refuse: FINISHED=PASSED, failed"
	case Skip:
		return "skip: FINISHED=SKIPPED, pending"
	}
	return "no expectation"
}

// transactionsExpectations are where the transactions engine
// (cmd/conformance-verifier's Config.Engine "transactions") differs
// from expectations: verifier.Transactions serves the Request Object
// by GET alone (RequestObjectHandler; Begin's links carry no
// request_uri_method), so the suite skips request-uri-method-post,
// whose summary says it's skipped when the Verifier's authorization
// request doesn't ask for request_uri_method=post.
var transactionsExpectations = map[string]Expectation{
	"oid4vp-1final-verifier-request-uri-method-post": Skip,
}

// expectationFor is what testName expects of the Verifier under
// engine, and whether it has an expectation at all.
func expectationFor(engine, testName string) (Expectation, bool) {
	if engine == EngineTransactions {
		if e, ok := transactionsExpectations[testName]; ok {
			return e, true
		}
	}
	e, ok := expectations[testName]
	return e, ok
}

// expectations names every module of the plan this repo drives, under
// either credential_format, with what it expects of the Verifier —
// from each module's summary and base class in the suite's source
// (src/main/java/net/openid/conformance/vp1finalverifier/: an
// AbstractVP1FinalVerifierNegativeTest subclass must be refused). The
// plan's own module list decides which of them a credential_format
// reaches.
var expectations = map[string]Expectation{
	"oid4vp-1final-verifier-happy-flow":                        Accept,
	"oid4vp-1final-verifier-minimal-cnf-jwk":                   Accept,
	"oid4vp-1final-verifier-request-uri-method-post":           Accept,
	"oid4vp-1final-verifier-request-uri-fetched-twice":         Accept,
	"oid4vp-1final-verifier-present-credential-without-status": Accept,

	"oid4vp-1final-verifier-invalid-session-transcript":   Refuse,
	"oid4vp-1final-verifier-invalid-kb-jwt-signature":     Refuse,
	"oid4vp-1final-verifier-invalid-credential-signature": Refuse,
	"oid4vp-1final-verifier-invalid-sd-hash":              Refuse,
	"oid4vp-1final-verifier-invalid-kb-jwt-nonce":         Refuse,
	"oid4vp-1final-verifier-invalid-kb-jwt-aud":           Refuse,
	// A Key Binding JWT issued a year ago, or a year from now: outside
	// any acceptable window (VP1FinalVerifierKbJwtIatIn{Past,Future}
	// extend the negative base class; cmd/conformance-verifier's
	// MaxKeyBindingAge is five minutes).
	"oid4vp-1final-verifier-kb-jwt-iat-in-past":   Refuse,
	"oid4vp-1final-verifier-kb-jwt-iat-in-future": Refuse,
	"oid4vp-1final-verifier-wrong-vct":            Refuse,
	// A credential whose Token Status List entry, or (an mdoc) whose
	// identifier list, the suite serves as revoked: the suite fails the
	// module if the Verifier never fetched the list
	// (EnsureVerifierFetchedRevocationList at FAILURE), so refusing it
	// for another reason doesn't pass.
	"oid4vp-1final-verifier-present-revoked-credential":            Refuse,
	"oid4vp-1final-verifier-present-credential-on-identifier-list": Refuse,
}

// notDriven names the plan's modules this repo doesn't drive, with why.
// A module the plan lists that is in neither this nor expectations
// fails the run.
var notDriven = map[string]string{}

// Grade compares one driven module's outcome with what expected says:
// the suite's status and result, the Verifier's own outcome as its
// result page reports it, and the module's log, which must hold no
// FAILURE and no WARNING. An accepted module's credential references a
// status list the Verifier must fetch, so even
// EnsureVerifierFetchedRevocationList's warning, which says it didn't,
// fails it.
func Grade(expected Expectation, status, result, verifierOutcome string, entries []conformancesuite.LogEntry) error {
	var wantResult, wantOutcome string
	switch expected {
	case Accept:
		wantResult, wantOutcome = "REVIEW", outcomeVerified
	case Refuse:
		wantResult, wantOutcome = "PASSED", outcomeFailed
	case Skip:
		wantResult, wantOutcome = "SKIPPED", outcomePending
	default:
		return errors.New("the module has no expectation")
	}
	var errs []error
	if err := conformancesuite.CheckFinished(status, result, wantResult); err != nil {
		errs = append(errs, err)
	}
	if verifierOutcome != wantOutcome {
		errs = append(errs, fmt.Errorf("the verifier's result page reports %q, want %q", verifierOutcome, wantOutcome))
	}
	if unexpected := conformancesuite.UnexpectedLogEntries(entries); len(unexpected) > 0 {
		errs = append(errs, fmt.Errorf("the module's log holds %s", conformancesuite.DescribeLogEntries(unexpected)))
	}
	return errors.Join(errs...)
}
