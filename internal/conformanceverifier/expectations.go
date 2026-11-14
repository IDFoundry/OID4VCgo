package conformanceverifier

import (
	"errors"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
	"github.com/idfoundry/oid4vcgo/verifier"
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
	// RefuseControl: a negative control's (DriveCRLControls). The
	// Verifier must refuse the presentation; the suite, whose module
	// expects it accepted, fails it, and its verdict isn't graded.
	RefuseControl
)

func (e Expectation) String() string {
	switch e {
	case Accept:
		return "accept: FINISHED=REVIEW, verified"
	case Refuse:
		return "refuse: FINISHED=PASSED, failed"
	case Skip:
		return "skip: FINISHED=SKIPPED, pending"
	case RefuseControl:
		return "refuse: suite verdict not graded, failed"
	}
	return "no expectation"
}

// expectationFor is what testName expects of the Verifier, and whether
// it has an expectation at all. Both engines of cmd/conformance-verifier
// expect the same: the transactions engine sets
// verifier.TransactionsConfig.RequestURIMethodPost, so its requests ask
// for request_uri_method=post as the default engine's do, and the suite
// runs request-uri-method-post for it too.
func expectationFor(testName string) (Expectation, bool) {
	e, ok := expectations[testName]
	return e, ok
}

// expectations names every module of the plan this repo drives, under
// either credential_format and either engine, with what it expects of the Verifier —
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

// refusals names, for every Refuse module, why the Verifier must refuse
// its presentation: what its result page's refusal must say, each a
// part of the text the page shows — the verifier.Reason the refusal
// carries ("reason: <reason>", which cmd/conformance-verifier's result
// page prints for a *verifier.Error under either engine) and a part of
// the error's own text naming the check the module breaks. The suite
// grades a refusal PASSED whatever its reason, so a Verifier that
// refused for another (an untrusted issuer, a configuration mistake)
// would otherwise pass. Read from the Verifier's refusals of the
// suite's own presentations, which cmd/conformance-verifier's result
// page and container log show.
var refusals = map[string][]string{
	// mdoc: the suite signs DeviceAuthentication over another
	// SessionTranscript, so the device signature over this request's
	// doesn't verify.
	"oid4vp-1final-verifier-invalid-session-transcript": {reasonHolderBinding, "mdoc: verify DeviceSignature: cose: ES256 signature verification failed"},
	"oid4vp-1final-verifier-invalid-kb-jwt-signature":   {reasonHolderBinding, "verify key binding JWT signature: jose: ES256 signature verification failed"},
	"oid4vp-1final-verifier-invalid-credential-signature": {
		"reason: " + string(verifier.ReasonInvalidCredential), "verify issuer JWT: jose: ES256 signature verification failed",
	},
	"oid4vp-1final-verifier-invalid-sd-hash":      {reasonHolderBinding, "key binding JWT sd_hash does not match the presented SD-JWT"},
	"oid4vp-1final-verifier-invalid-kb-jwt-nonce": {reasonHolderBinding, "key binding JWT is for another request: its nonce does not match"},
	"oid4vp-1final-verifier-invalid-kb-jwt-aud":   {reasonHolderBinding, "key binding JWT is for another request: its aud does not match"},
	"oid4vp-1final-verifier-kb-jwt-iat-in-past":   {reasonHolderBinding, "key binding JWT is too old"},
	"oid4vp-1final-verifier-kb-jwt-iat-in-future": {reasonHolderBinding, "key binding JWT iat is too far in the future"},
	"oid4vp-1final-verifier-wrong-vct": {
		"reason: " + string(verifier.ReasonNotAnswered), `credential's own vct "urn:conformance-suite:unrequested:credential:1", and its aka_vcts, are not among the requested vct_values`,
	},
	// A status refusal carries no verifier.Reason: the status check runs
	// once the presentation itself has verified.
	"oid4vp-1final-verifier-present-revoked-credential":            {"credential status: statuslist: the referenced token's status is INVALID (revoked)"},
	"oid4vp-1final-verifier-present-credential-on-identifier-list": {"credential status: identifierlist: the MSO's identifier is on its identifier list: it is revoked"},
}

// reasonHolderBinding is the result page's line for a refusal whose
// verifier.Reason is ReasonHolderBinding.
var reasonHolderBinding = "reason: " + string(verifier.ReasonHolderBinding)

// notDriven names the plan's modules this repo doesn't drive, with why.
// A module the plan lists that is in neither this nor expectations
// fails the run.
var notDriven = map[string]string{}

// Grade compares one driven module's outcome with what expected says:
// the suite's status and result, the Verifier's own outcome as its
// result page reports it, why it refused (refusal, the page's text) for
// a Refuse module, which must hold every one of wantRefusal, and the
// module's log, which must hold no FAILURE and no WARNING. An accepted
// module's credential references a status list the Verifier must
// fetch, so even EnsureVerifierFetchedRevocationList's warning, which
// says it didn't, fails it.
func Grade(expected Expectation, wantRefusal []string, status, result, verifierOutcome, refusal string, entries []conformancesuite.LogEntry) error {
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
	} else if expected == Refuse {
		if err := checkRefusal(wantRefusal, refusal); err != nil {
			errs = append(errs, err)
		}
	}
	if unexpected := conformancesuite.UnexpectedLogEntries(entries); len(unexpected) > 0 {
		errs = append(errs, fmt.Errorf("the module's log holds %s", conformancesuite.DescribeLogEntries(unexpected)))
	}
	return errors.Join(errs...)
}

// checkRefusal reports whether refusal, the result page's text, holds
// every one of want: a Refuse module with none classified fails, as an
// unclassified module does.
func checkRefusal(want []string, refusal string) error {
	if len(want) == 0 {
		return errors.New("the module has no expected refusal: classify it in internal/conformanceverifier's refusals")
	}
	for _, w := range want {
		if !strings.Contains(refusal, w) {
			return fmt.Errorf("the verifier refused with %q, want a refusal naming %q", refusal, w)
		}
	}
	return nil
}
