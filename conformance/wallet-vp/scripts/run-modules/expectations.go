package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/conformancesuite"
)

// walletAction is what cmd/conformance-wallet-vp did with a module's
// request.
type walletAction string

const (
	// actionPresented: it presented a credential at the response_uri.
	actionPresented walletAction = "presented"
	// actionRefused: it refused the request without answering the
	// response_uri (a direct_post.jwt drive answered non-200; a DC API
	// answer carried an exception).
	actionRefused walletAction = "refused"
)

// actionSentError is the action of sending an OpenID4VP error response
// with code to the response_uri.
func actionSentError(code string) walletAction { return walletAction("error " + code) }

// expectation is what one module of oid4vp-1final-wallet-haip-test-plan
// expects the wallet to do, and the suite's verdict when it does.
type expectation struct {
	// action is what the wallet must do with the request.
	action walletAction
	// result is the suite's result once it has: PASSED, or REVIEW for
	// a module the wallet must refuse without answering, which only a
	// screenshot of the wallet's error can end.
	result string
	// allowedWarnings are the WARNING conditions the module may log,
	// each with its reason in a comment.
	allowedWarnings []string
	// refusal, for an actionRefused expectation, is what the wallet's
	// refusal must say: parts of the text it refused with (its
	// direct_post.jwt drive's non-200 body, or its DC API answer's
	// exception message), naming the check the module breaks, every
	// one of which it must hold. A refusal for another reason fails
	// the module.
	refusal []string
}

func (e expectation) String() string {
	s := string(e.action) + ", FINISHED=" + e.result
	if len(e.refusal) > 0 {
		s += fmt.Sprintf(", refusal naming %q", e.refusal)
	}
	return s
}

// refuseFor is the expectation of a module whose request the wallet
// must refuse without answering, for the reason its refusal text names
// (expectation.refusal).
func refuseFor(refusal ...string) expectation {
	return expectation{action: actionRefused, result: "REVIEW", refusal: refusal}
}

var (
	expectPresent        = expectation{action: actionPresented, result: "PASSED"}
	expectInvalidRequest = expectation{action: actionSentError("invalid_request"), result: "PASSED"}
	expectAccessDenied   = expectation{action: actionSentError("access_denied"), result: "PASSED"}
)

// expectations names every module of the plan this repo drives, under
// any response_mode and credential_format, with what it expects of the
// wallet — from each module's summary in the suite's source
// (src/main/java/net/openid/conformance/vp1finalwallet/). The plan's
// own module list decides which of them a variant reaches; a module it
// lists that isn't named here fails the run.
//
// The error codes are the ones the suite checks
// (EnsureInvalidTransactionDataError,
// EnsureAuthorizationEndpointErrorIsAccessDenied, ...): a wallet that
// sends another fails the module.
var expectations = map[string]expectation{
	"oid4vp-1final-wallet-happy-flow":                         expectPresent,
	"oid4vp-1final-wallet-alternate-happy-flow":               expectPresent,
	"oid4vp-1final-wallet-request-uri-method-post":            expectPresent,
	"oid4vp-1final-wallet-ignores-unusable-encryption-key":    expectPresent,
	"oid4vp-1final-wallet-fewer-claims-than-available":        expectPresent,
	"oid4vp-1final-wallet-optional-credential-set":            expectPresent,
	"oid4vp-1final-wallet-no-claims-in-dcql-query":            expectPresent,
	"oid4vp-1final-wallet-all-mandatory-claims":               expectPresent,
	"oid4vp-1final-wallet-pid-claims-path-array-index":        expectPresent,
	"oid4vp-1final-wallet-pid-claims-path-array-all-elements": expectPresent,
	"oid4vp-1final-wallet-pid-claims-path-object-member":      expectPresent,
	"oid4vp-1final-wallet-age-over-18":                        expectPresent,
	// One of a multi-signed request's two signatures is invalid: a
	// wallet must verify at least one valid signature, so it answers.
	"oid4vp-1final-wallet-multisigned-one-invalid-signature": expectPresent,

	// A request the wallet can't trust: it must not answer the
	// response_uri the request names at all, and its refusal must name
	// what the module breaks — a wallet that refuses for some other
	// reason (an unreachable request_uri, a trust anchor it lost) would
	// otherwise pass. The texts are wallet's own errors, as
	// cmd/conformance-wallet-vp answers them.
	// Under the DC API's multi-signed requests, the wallet reports each
	// signature's failure ("no signature verifies: signature 0: ..."),
	// which holds the same texts.
	"oid4vp-1final-wallet-negative-test-invalid-request-object-signature": refuseFor("signature verification failed: jose: ES256 signature verification failed"),
	"oid4vp-1final-wallet-negative-test-invalid-request-object-typ":       refuseFor(`typ = "jwt", want "oauth-authz-req+jwt"`),
	"oid4vp-1final-wallet-negative-test-missing-request-object-typ":       refuseFor(`typ = "", want "oauth-authz-req+jwt"`),
	// The Request Object's client_id isn't the request's.
	"oid4vp-1final-wallet-negative-test-mismatched-client-id": refuseFor(`payload client_id "x509_hash:`, `-mismatched" does not match "x509_hash:`),
	// A client_id prefix the wallet doesn't know: it accepts only
	// x509_hash, so it reports the client_id as not the x5c leaf's.
	"oid4vp-1final-wallet-negative-test-invalid-client-id-prefix": refuseFor(`client_id "invalid_scheme:`, `does not match x5c leaf's own x509_hash "x509_hash:`),
	// DC API: the origin the browser reports isn't one the signed
	// request's expected_origins lists.
	"oid4vp-1final-wallet-negative-test-wrong-expected-origins": refuseFor("is not in expected_origins"),

	// A trusted request the wallet can't fulfil: it answers with an
	// error response.
	"oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post":    expectInvalidRequest,
	"oid4vp-1final-wallet-negative-test-missing-nonce":                    expectInvalidRequest,
	"oid4vp-1final-wallet-negative-test-unknown-transaction-data-type":    {action: actionSentError("invalid_transaction_data"), result: "PASSED"},
	"oid4vp-1final-wallet-negative-test-required-non-matching-credential": expectAccessDenied,
	"oid4vp-1final-wallet-negative-test-claim-not-in-credential":          expectAccessDenied,
}

// expectationFor is testName's expectation, or an error naming a module
// the plan lists that nobody has classified.
func expectationFor(testName string) (expectation, error) {
	exp, ok := expectations[testName]
	if !ok {
		return expectation{}, fmt.Errorf("the plan lists %s, which has no expectation: classify it in run-modules' expectations", testName)
	}
	return exp, nil
}

// grade compares what the wallet did (action, and refusal, the text it
// refused with) and the suite's verdict (status, result, and the
// module's log, which must hold no FAILURE and no WARNING exp doesn't
// allow) with exp.
func grade(exp expectation, action walletAction, refusal, status, result string, entries []conformancesuite.LogEntry) error {
	var errs []error
	if action != exp.action {
		errs = append(errs, fmt.Errorf("the wallet %s, want %s", action, exp.action))
	} else if exp.action == actionRefused {
		if err := checkRefusal(exp.refusal, refusal); err != nil {
			errs = append(errs, err)
		}
	}
	if err := conformancesuite.CheckFinished(status, result, exp.result); err != nil {
		errs = append(errs, err)
	}
	if unexpected := conformancesuite.UnexpectedLogEntries(entries, exp.allowedWarnings...); len(unexpected) > 0 {
		errs = append(errs, fmt.Errorf("the module's log holds %s", conformancesuite.DescribeLogEntries(unexpected)))
	}
	return errors.Join(errs...)
}

// checkRefusal reports whether refusal, the text the wallet refused
// with, holds every one of want: a refuse expectation naming none
// fails, as an unclassified module does.
func checkRefusal(want []string, refusal string) error {
	if len(want) == 0 {
		return errors.New("the module has no expected refusal: name it in run-modules' expectations")
	}
	for _, w := range want {
		if !strings.Contains(refusal, w) {
			return fmt.Errorf("the wallet refused with %q, want a refusal naming %q", refusal, w)
		}
	}
	return nil
}
