package mobile

import (
	"context"
	"encoding/json"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// ABIVersion is the version of this package's API across the gomobile
// boundary: its functions, objects, JSON results and error codes. It
// changes whenever any of them changes incompatibly.
const ABIVersion = 6

// Error codes, at the start of every error's text in brackets.
const (
	// CodeInvalidInput: an argument was malformed.
	CodeInvalidInput = "invalid_input"
	// CodePlatform: a callback into the app failed.
	CodePlatform = "platform"
	// CodeNetwork: a request couldn't be made, got no answer, or timed
	// out.
	CodeNetwork = "network"
	// CodeUnavailable: the service answered that it's failing or busy
	// (HTTP 5xx or 429); trying again later may succeed.
	CodeUnavailable = "unavailable"
	// CodeCancelled: the Operation was cancelled.
	CodeCancelled = "cancelled"
	// CodeNotFound: no key, credential or deferred credential with that
	// ID.
	CodeNotFound = "not_found"
	// CodeWrongStep: a session method called out of turn, or after
	// Close.
	CodeWrongStep = "wrong_step"
	// CodeAuthorizationDenied: the Authorization Server refused, e.g.
	// the holder declined at the issuer (the OAuth error code follows in
	// the message).
	CodeAuthorizationDenied = "authorization_denied"
	// CodeCredentialDenied: the issuer refused a deferred credential.
	CodeCredentialDenied = "credential_denied" //nolint:gosec // an error code, not a credential
	// CodeNoMatchingCredential: nothing the wallet holds answers the
	// Verifier's request.
	CodeNoMatchingCredential = "no_matching_credential"
	// CodeDeliveryUnknown: sending a presentation failed in a way that
	// leaves it unknown whether the Verifier received it. It isn't sent
	// again: that could present twice.
	CodeDeliveryUnknown = "delivery_unknown"
	// CodeProtocol: an issuer, Authorization Server or Verifier answered
	// with an error, or with something the wallet refuses.
	CodeProtocol = "protocol"
	// CodeInternal: a bug, or anything else.
	CodeInternal = "internal"
)

// Error is an error as it crosses the boundary: its text is
// "[Code] Message", or "[Code:Detail] Message" when the issuer,
// Authorization Server or Verifier answered with an error code of its
// own (Detail: an OAuth error code such as invalid_grant, which a wrong
// PIN gets).
type Error struct {
	Code    string
	Detail  string
	Message string
}

func (e *Error) Error() string {
	if e.Detail != "" {
		return "[" + e.Code + ":" + e.Detail + "] " + e.Message
	}
	return "[" + e.Code + "] " + e.Message
}

func newError(code string, err error) error {
	return &Error{Code: code, Message: cleanText(err.Error())}
}

// result is the JSON envelope's common part.
type result struct {
	ABI int `json:"abi"`
}

// ParseRequestLink parses an OpenID4VP request link (openid4vp://?…) and
// returns {"abi", "client_id", "request_uri", "request_uri_method"}.
func ParseRequestLink(link string) (string, error) {
	parsed, err := wallet.ParseAuthorizationRequestLink(link)
	if err != nil {
		return "", newError(CodeInvalidInput, err)
	}
	out, err := json.Marshal(struct {
		result
		ClientID         string `json:"client_id"`
		RequestURI       string `json:"request_uri"`
		RequestURIMethod string `json:"request_uri_method,omitempty"`
	}{result{ABIVersion}, parsed.ClientID, parsed.RequestURI, parsed.RequestURIMethod})
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	return string(out), nil
}

// Operation is a long call the app can cancel from another thread.
type Operation struct {
	ctx    context.Context
	cancel context.CancelFunc
}

// NewOperation returns an Operation that times out after timeoutMillis
// (0: never).
func NewOperation(timeoutMillis int64) *Operation {
	if timeoutMillis > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMillis)*time.Millisecond)
		return &Operation{ctx: ctx, cancel: cancel}
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Operation{ctx: ctx, cancel: cancel}
}

// Cancel cancels the operation: a call using it returns a "cancelled"
// error. Safe to call more than once, and from any thread.
func (o *Operation) Cancel() { o.cancel() }

// context is op's context; a nil Operation never ends.
func (o *Operation) context() context.Context {
	if o == nil {
		return context.Background()
	}
	return o.ctx
}
