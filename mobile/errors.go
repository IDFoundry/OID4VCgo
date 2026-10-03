package mobile

import (
	"context"
	"errors"
	"net"
	"net/url"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// classify gives err its code as it crosses the boundary.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var mobileErr *Error
	var denied *walletflow.AuthorizationDeniedError
	var protocol *wallet.Error
	var rejected *wallet.DirectPostRejectedError
	var urlErr *url.Error
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return newError(CodeCancelled, err)
	case errors.As(err, &mobileErr):
		// A KeyStore or other callback's error, inside walletflow's
		// context.
		return &Error{Code: mobileErr.Code, Message: err.Error()}
	case errors.Is(err, walletflow.ErrWrongStep):
		return newError(CodeWrongStep, err)
	case errors.As(err, &denied):
		return &Error{Code: CodeAuthorizationDenied, Detail: errorCode(denied.Code), Message: err.Error()}
	case errors.Is(err, walletflow.ErrCredentialDenied):
		return newError(CodeCredentialDenied, err)
	case errors.Is(err, walletflow.ErrNoMatchingCredential):
		return newError(CodeNoMatchingCredential, err)
	case errors.Is(err, walletflow.ErrNotFound):
		return newError(CodeNotFound, err)
	case errors.As(err, &protocol):
		return &Error{Code: CodeProtocol, Detail: errorCode(protocol.Code), Message: err.Error()}
	case errors.As(err, &rejected):
		return &Error{Code: CodeProtocol, Detail: errorCode(rejected.Code), Message: err.Error()}
	case errors.As(err, &urlErr) && urlErr.Op == "parse":
		// A malformed link: don't echo it, it may carry a
		// pre-authorized code.
		return newError(CodeInvalidInput, errors.New("malformed link or URL"))
	case errors.As(err, &urlErr), errors.As(err, &netErr):
		return newError(CodeNetwork, err)
	default:
		return newError(CodeProtocol, err)
	}
}

// errorCode is code if it's a plausible OAuth error code (RFC 6749
// §5.2: printable ASCII but space, quote and backslash; here letters,
// digits and underscores, which every registered one is), and "" if not:
// it's the remote party's text, so it's never let near the bracketed
// prefix unchecked.
func errorCode(code string) string {
	if code == "" || len(code) > 64 {
		return ""
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_' {
			return ""
		}
	}
	return code
}
