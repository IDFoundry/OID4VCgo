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
)

func (e Expectation) String() string {
	switch e {
	case Accept:
		return "accept: FINISHED=REVIEW, verified"
	case Refuse:
		return "refuse: FINISHED=PASSED, failed"
	}
	return "no expectation"
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
}

// notStatusChecked is why the revocation modules aren't driven.
const notStatusChecked = "cmd/conformance-verifier checks no credential status in the suite's runs (NoStatusCheck), so it can't refuse a revoked credential; driving this module needs a status_list trust anchor for the suite's per-run issuer"

// notDriven names the plan's modules this repo doesn't drive, with why.
// A module the plan lists that is in neither this nor expectations
// fails the run.
var notDriven = map[string]string{
	"oid4vp-1final-verifier-present-revoked-credential":            notStatusChecked,
	"oid4vp-1final-verifier-present-credential-on-identifier-list": notStatusChecked,
}

// acceptWarnings are the WARNING conditions a module that must be
// accepted may log (REVIEW hides them in its result), each for a known
// reason:
//
//   - EnsureVerifierFetchedRevocationList: the suite's credentials
//     carry a status reference the Verifier never fetches, as it
//     checks no status in these runs (see notStatusChecked). The suite
//     makes this a warning, not a failure, as no specification makes
//     the check mandatory.
var acceptWarnings = []string{"EnsureVerifierFetchedRevocationList"}

// Grade compares one driven module's outcome with what expected says:
// the suite's status and result, the Verifier's own outcome as its
// result page reports it, and the module's log, which must hold no
// FAILURE and no WARNING but those acceptWarnings allows an accepted
// module.
func Grade(expected Expectation, status, result, verifierOutcome string, entries []conformancesuite.LogEntry) error {
	var wantResult, wantOutcome string
	var allowed []string
	switch expected {
	case Accept:
		wantResult, wantOutcome, allowed = "REVIEW", outcomeVerified, acceptWarnings
	case Refuse:
		wantResult, wantOutcome = "PASSED", outcomeFailed
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
	if unexpected := conformancesuite.UnexpectedLogEntries(entries, allowed...); len(unexpected) > 0 {
		errs = append(errs, fmt.Errorf("the module's log holds %s", conformancesuite.DescribeLogEntries(unexpected)))
	}
	return errors.Join(errs...)
}
