package mobile

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/idfoundry/fapigo/client"

	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// classify gives err its code as it crosses the boundary, with a message
// fit for an app's logs: it never carries what the issuer,
// Authorization Server or Verifier said in its own words (an
// error_description, an error body), a URL's path or query (which can
// carry a pre-authorized code, a request_uri or a response_code), or
// control characters. The remote party's OAuth error code, checked to be
// a plain token, is the Detail.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var mobileErr *Error
	var denied *walletflow.AuthorizationDeniedError
	var protocol *wallet.Error
	var rejected *wallet.DirectPostRejectedError
	var clientErr *client.Error
	var urlErr *url.Error
	var netErr net.Error
	switch {
	case errors.Is(err, context.Canceled):
		return newError(CodeCancelled, errors.New("cancelled"))
	case errors.Is(err, context.DeadlineExceeded):
		// A request's own timeout, or the Operation's: either way, the
		// service didn't answer in time.
		return newError(CodeNetwork, errors.New("the request timed out"))
	case errors.Is(err, walletflow.ErrTLSPinMismatch):
		return newError(CodeTLSPin, walletflow.ErrTLSPinMismatch)
	case errors.As(err, &mobileErr):
		// A KeyStore or other callback's error, inside walletflow's
		// context.
		return newError(mobileErr.Code, err)
	case errors.Is(err, walletflow.ErrWrongStep):
		return newError(CodeWrongStep, err)
	case errors.As(err, &denied):
		return &Error{Code: CodeAuthorizationDenied, Detail: errorCode(denied.Code), Message: "the authorization server didn't authorize the request"}
	case errors.Is(err, walletflow.ErrCredentialDenied):
		return newError(CodeCredentialDenied, err)
	case errors.Is(err, walletflow.ErrNoMatchingCredential):
		return newError(CodeNoMatchingCredential, err)
	case errors.Is(err, walletflow.ErrInvalidSelection):
		return newError(CodeInvalidSelection, err)
	case errors.Is(err, walletflow.ErrLinkable):
		// What the holder agreed to no longer holds: the selection would
		// now present a copy another Verifier has seen. Nothing was sent.
		return newError(CodeInvalidSelection, walletflow.ErrLinkable)
	case errors.Is(err, walletflow.ErrReissueRequired):
		return newError(CodeReissueRequired, err)
	case errors.Is(err, walletflow.ErrDeliveryUnknown):
		// Before network: sending again could present twice.
		return newError(CodeDeliveryUnknown, walletflow.ErrDeliveryUnknown)
	case errors.Is(err, wallet.ErrUntrustedVerifier):
		return newError(CodeUntrustedVerifier, wallet.ErrUntrustedVerifier)
	case errors.Is(err, walletflow.ErrNotFound):
		return newError(CodeNotFound, err)
	case errors.As(err, &protocol):
		return refused(protocol.HTTPStatus, protocol.Code, "the issuer or authorization server")
	case errors.As(err, &rejected):
		return refused(rejected.StatusCode, rejected.Code, "the verifier")
	case errors.As(err, &urlErr) && urlErr.Op == "parse":
		// A malformed link: don't echo it, it may carry a
		// pre-authorized code.
		return newError(CodeInvalidInput, errors.New("malformed link or URL"))
	case errors.As(err, &urlErr):
		// Its URL can carry a request_uri or a code: only the failure.
		return newError(CodeNetwork, fmt.Errorf("network error: %w", urlErr.Err))
	case errors.As(err, &netErr):
		return newError(CodeNetwork, fmt.Errorf("network error: %w", netErr))
	case errors.As(err, &clientErr):
		if resp, ok := clientErr.ServerResponse(); ok {
			return refused(resp.HTTPStatus, resp.Code, "the authorization server")
		}
		return newError(CodeProtocol, fmt.Errorf("the authorization server's answer couldn't be used (%s)", clientErr.Code()))
	default:
		return newError(CodeProtocol, err)
	}
}

// refused is a remote party's error response: by whom, its HTTP status
// and OAuth error code, never its description. A 5xx or 429 is
// unavailable, worth trying again later.
func refused(status int, code, by string) error {
	c := CodeProtocol
	if status >= http.StatusInternalServerError || status == http.StatusTooManyRequests {
		c = CodeUnavailable
	}
	msg := by + " refused the request"
	if status != 0 {
		msg += fmt.Sprintf(" (HTTP %d)", status)
	}
	return &Error{Code: c, Detail: errorCode(code), Message: msg}
}

// maxMessage caps an error message's length, in runes.
const maxMessage = 300

// urlPattern matches a URL, to cut it to its scheme and host.
var urlPattern = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://[^\s"'<>]*`)

// cleanText is s fit for an app's logs: each URL cut to its scheme and
// host, control characters made spaces, at most maxMessage runes.
func cleanText(s string) string {
	s = urlPattern.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" {
			return "<URL>"
		}
		return u.Scheme + "://" + u.Host
	})
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > maxMessage {
		s = string(r[:maxMessage]) + "…"
	}
	return s
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
