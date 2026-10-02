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
		return newError(CodeAuthorizationDenied, err)
	case errors.Is(err, walletflow.ErrCredentialDenied):
		return newError(CodeCredentialDenied, err)
	case errors.Is(err, walletflow.ErrNoMatchingCredential):
		return newError(CodeNoMatchingCredential, err)
	case errors.Is(err, walletflow.ErrNotFound):
		return newError(CodeNotFound, err)
	case errors.As(err, &protocol), errors.As(err, &rejected):
		return newError(CodeProtocol, err)
	case errors.As(err, &urlErr), errors.As(err, &netErr):
		return newError(CodeNetwork, err)
	default:
		return newError(CodeProtocol, err)
	}
}
