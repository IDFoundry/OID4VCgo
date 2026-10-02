package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// ABIVersion is the version of this package's API across the gomobile
// boundary: its functions, objects, JSON results and error codes. It
// changes whenever any of them changes incompatibly.
const ABIVersion = 0

// Error codes, at the start of every error's text in brackets.
const (
	// CodeInvalidInput: an argument was malformed.
	CodeInvalidInput = "invalid_input"
	// CodePlatform: a callback into the app failed.
	CodePlatform = "platform"
	// CodeNetwork: a request failed or got an unexpected answer.
	CodeNetwork = "network"
	// CodeCancelled: the Operation was cancelled.
	CodeCancelled = "cancelled"
	// CodeNotFound: the KeyStore holds no key with that ID.
	CodeNotFound = "not_found"
	// CodeInternal: anything else.
	CodeInternal = "internal"
)

// Error is an error as it crosses the boundary: its text is
// "[Code] Message".
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return "[" + e.Code + "] " + e.Message }

func newError(code string, err error) error {
	return &Error{Code: code, Message: err.Error()}
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

// fetcher is the spike's shared HTTP client.
var fetcher = struct {
	sync.Once
	c *http.Client
}{}

func httpClient() *http.Client {
	fetcher.Do(func() { fetcher.c = &http.Client{Timeout: 30 * time.Second} })
	return fetcher.c
}

// maxFetchBytes bounds what Fetch reads.
const maxFetchBytes = 1 << 20

// Fetch GETs url under op and returns its body as text — the spike's
// stand-in for a protocol request the app can cancel.
func Fetch(op *Operation, url string) (string, error) {
	if op == nil {
		return "", newError(CodeInvalidInput, errors.New("no operation"))
	}
	req, err := http.NewRequestWithContext(op.ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", newError(CodeInvalidInput, err)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		if op.ctx.Err() != nil {
			return "", newError(CodeCancelled, op.ctx.Err())
		}
		return "", newError(CodeNetwork, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))
	if err != nil {
		if op.ctx.Err() != nil {
			return "", newError(CodeCancelled, op.ctx.Err())
		}
		return "", newError(CodeNetwork, err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", newError(CodeNetwork, fmt.Errorf("status %d", resp.StatusCode))
	}
	return string(body), nil
}
