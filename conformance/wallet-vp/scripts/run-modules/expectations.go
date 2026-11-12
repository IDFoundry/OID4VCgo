package main

import (
	"errors"
	"fmt"

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
}

func (e expectation) String() string { return string(e.action) + ", FINISHED=" + e.result }

var (
	expectPresent        = expectation{action: actionPresented, result: "PASSED"}
	expectRefuse         = expectation{action: actionRefused, result: "REVIEW"}
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
	// response_uri the request names at all.
	"oid4vp-1final-wallet-negative-test-invalid-request-object-signature": expectRefuse,
	"oid4vp-1final-wallet-negative-test-invalid-request-object-typ":       expectRefuse,
	"oid4vp-1final-wallet-negative-test-missing-request-object-typ":       expectRefuse,
	"oid4vp-1final-wallet-negative-test-mismatched-client-id":             expectRefuse,
	"oid4vp-1final-wallet-negative-test-invalid-client-id-prefix":         expectRefuse,
	"oid4vp-1final-wallet-negative-test-wrong-expected-origins":           expectRefuse,

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

// grade compares what the wallet did (action) and the suite's verdict
// (status, result, and the module's log, which must hold no FAILURE
// and no WARNING exp doesn't allow) with exp.
func grade(exp expectation, action walletAction, status, result string, entries []conformancesuite.LogEntry) error {
	var errs []error
	if action != exp.action {
		errs = append(errs, fmt.Errorf("the wallet %s, want %s", action, exp.action))
	}
	if err := conformancesuite.CheckFinished(status, result, exp.result); err != nil {
		errs = append(errs, err)
	}
	if unexpected := conformancesuite.UnexpectedLogEntries(entries, exp.allowedWarnings...); len(unexpected) > 0 {
		errs = append(errs, fmt.Errorf("the module's log holds %s", conformancesuite.DescribeLogEntries(unexpected)))
	}
	return errors.Join(errs...)
}
