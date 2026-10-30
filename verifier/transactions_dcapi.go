package verifier

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/strictjson"
	"github.com/idfoundry/oid4vcgo/internal/weborigin"
)

// DCAPIProtocolSigned is the Digital Credentials API protocol of a
// signed OpenID4VP request (OpenID4VP 1.0 Appendix A.3.2.1, JWS Compact
// Serialization), the only kind this package builds.
const DCAPIProtocolSigned = "openid4vp-v1-signed"

// MaxDCAPIResponseBytes bounds the data HandleDCAPIResponse takes: the
// page's answer, as the Digital Credentials API returned it. Bound the
// request that carries it to the page's endpoint by this much too.
const MaxDCAPIResponseBytes = maxResponseBodyBytes

// DCAPIRequest is one entry of navigator.credentials.get's
// digital.requests: encode it as JSON for the page.
type DCAPIRequest struct {
	Protocol string           `json:"protocol"`
	Data     DCAPIRequestData `json:"data"`
}

// DCAPIRequestData is a signed request's data: the Request Object.
type DCAPIRequestData struct {
	Request string `json:"request"`
}

// BegunDCAPI is a newly created Digital Credentials API presentation
// request.
type BegunDCAPI struct {
	// ID identifies the request: the handle HandleDCAPIResponse, Lookup
	// and Close take. Unlike a redirect request's, it isn't in anything
	// the Wallet sees, but treat it as public all the same: the browser
	// binding is what protects the request.
	ID string

	// Request is what the page passes to navigator.credentials.get.
	Request DCAPIRequest
}

// BeginDCAPI creates a presentation request for query over the Digital
// Credentials API (OpenID4VP 1.0 Appendix A): a signed Request Object,
// response mode dc_api.jwt (HAIP 1.0 §5.2), with origin, the origin of
// the page that will make the request, as its only expected_origins
// entry. The page's answer comes back through HandleDCAPIResponse;
// Lookup and Close work as for Begin's requests.
//
// origin is the page's serialized origin (scheme, host and optional
// port): the answer is verified as bound to it (Appendix A.4). It is
// normalized as TransactionsConfig.Origins are (its scheme and host
// lowercased, without a trailing "/" or the scheme's default port), and
// must then be one of them, which under AssuranceProduction must be
// set; under AssuranceDevelopment without them, any https origin, or
// loopback http, as browsers offer the Digital Credentials API to
// secure contexts only. browserBinding is as for Begin, and the page's
// answer must arrive with it.
func (t *Transactions) BeginDCAPI(ctx context.Context, query dcql.Query, browserBinding, origin string) (BegunDCAPI, error) {
	if len(browserBinding) < MinBrowserBindingLength {
		return BegunDCAPI{}, fmt.Errorf("verifier: transactions: a browser binding of at least %d bytes is required: an unguessable random token", MinBrowserBindingLength)
	}
	origin = weborigin.Normalize(origin)
	if err := t.checkDCAPIOrigin(origin); err != nil {
		return BegunDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	if err := t.checkVerifies(query); err != nil {
		return BegunDCAPI{}, err
	}
	id, err := t.randomToken()
	if err != nil {
		return BegunDCAPI{}, err
	}
	built, err := t.v.BuildDCAPIAuthorizationRequest(BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{origin}})
	if err != nil {
		return BegunDCAPI{}, fmt.Errorf("verifier: transactions: %w", err)
	}
	// No KeyID and no State: the answer comes back through the page, to
	// this ID, never routed by its key or state from the response
	// endpoint.
	tx := Transaction{
		ID: id, Nonce: built.Nonce, Query: query, ResponseDecryptionKey: built.ResponseDecryptionKey,
		Origin: origin, Status: TransactionPending, Owner: t.owner,
	}
	tx.ExpiresAt, tx.RetainUntil = t.expiry()
	sum := sha256.Sum256([]byte(browserBinding))
	tx.BrowserBindingHash = sum[:]
	if err := t.create(ctx, tx); err != nil {
		return BegunDCAPI{}, err
	}
	return BegunDCAPI{ID: id, Request: DCAPIRequest{Protocol: DCAPIProtocolSigned, Data: DCAPIRequestData{Request: built.RequestObject}}}, nil
}

// checkDCAPIOrigin checks BeginDCAPI's origin, normalized, is one of
// TransactionsConfig.Origins (normalized by NewTransactions), or
// without them, under AssuranceDevelopment, one a page can use the
// Digital Credentials API from.
func (t *Transactions) checkDCAPIOrigin(origin string) error {
	switch {
	case len(t.cfg.Origins) > 0:
		if !slices.Contains(t.cfg.Origins, origin) {
			return fmt.Errorf("origin %q (normalized) isn't one of TransactionsConfig.Origins %q", origin, t.cfg.Origins)
		}
		return nil
	case t.v.cfg.Assurance == AssuranceProduction:
		return errors.New("under AssuranceProduction, BeginDCAPI needs TransactionsConfig.Origins: the origins of the pages that make Digital Credentials API requests")
	}
	return weborigin.CheckPage(origin, true)
}

// HandleDCAPIResponse processes the answer to the Digital Credentials
// API request id, which the page posts back with the browser binding
// the request began with: data is the DigitalCredential's data as the
// browser returned it, {"response": JWE} or Appendix A.4's
// {"error": code}. It checks the binding and that the request is still
// pending, decrypts the response with the request's key, verifies it
// against the request's query and nonce, bound to its origin, runs
// TransactionsConfig.Accept, and completes the request at most once,
// returning its result.
//
// A refused answer, a Wallet's error included, is recorded as the
// request's LastError and returned, and the request stays open, as for
// HandleResponse: an error doesn't prove the holder declined (its
// contents come from whatever answered), and the page may try again
// within the request's lifetime. A Wallet's error is a *ResponseError.
// Close the request to end it. An answer arriving with another browser
// binding is refused with ErrWrongBrowser and leaves the request as it
// was.
func (t *Transactions) HandleDCAPIResponse(ctx context.Context, id, browserBinding string, data []byte) (TransactionView, error) {
	tx, err := t.get(ctx, id)
	if err != nil {
		return TransactionView{}, storeFault(err)
	}
	if tx.Origin == "" {
		return TransactionView{}, ErrTransactionUnknown
	}
	if !bindingMatches(tx.BrowserBindingHash, browserBinding) {
		return TransactionView{}, ErrWrongBrowser
	}
	if err := t.checkPending(tx); err != nil {
		return TransactionView{}, err
	}
	result, err := t.verifyDCAPI(ctx, tx, data)
	if err != nil {
		t.recordFailure(ctx, id, err)
		return TransactionView{}, err
	}
	var view TransactionView
	err = t.update(ctx, id, func(cur *Transaction) error {
		if err := t.checkPending(*cur); err != nil {
			return err
		}
		cur.Result, cur.LastError, cur.Status = &result, "", TransactionDone
		view = t.release(cur)
		return nil
	})
	if err != nil {
		return TransactionView{}, storeFault(err)
	}
	return view, nil
}

// verifyDCAPI decrypts, verifies and accepts one Digital Credentials
// API answer to tx.
func (t *Transactions) verifyDCAPI(ctx context.Context, tx Transaction, data []byte) (VerifyResponseResult, error) {
	if len(data) > MaxDCAPIResponseBytes {
		return VerifyResponseResult{}, newError(ReasonMalformed, fmt.Sprintf("the Digital Credentials API response is over %d bytes", MaxDCAPIResponseBytes), nil)
	}
	var answer struct {
		Response string `json:"response"`
		Error    string `json:"error"`
	}
	if err := strictjson.Unmarshal(data, &answer); err != nil {
		return VerifyResponseResult{}, newError(ReasonMalformed, "the Digital Credentials API response isn't a JSON object", err)
	}
	switch {
	case answer.Response == "" && answer.Error != "":
		// Appendix A.4's error, which the platform carried unencrypted.
		return VerifyResponseResult{}, &ResponseError{Code: answer.Error}
	case answer.Response == "":
		return VerifyResponseResult{}, newError(ReasonMalformed, `the Digital Credentials API response has neither "response" nor "error"`, nil)
	}
	parsed, err := t.v.ParseDirectPostJWTResponse(answer.Response, tx.ResponseDecryptionKey)
	if err != nil {
		// An encrypted error is this request's: only its key decrypts it.
		return VerifyResponseResult{}, err
	}
	return t.verifyParsed(ctx, tx, parsed)
}
