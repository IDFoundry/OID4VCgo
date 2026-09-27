package wallet

import (
	"errors"
	"fmt"
	"net/url"
)

// Values of AuthorizationRequestLink.RequestURIMethod (OID4VP §5.10).
const (
	RequestURIMethodGet  = "get"
	RequestURIMethodPost = "post"
)

// AuthorizationRequestLink is what an OpenID4VP invocation — an
// openid4vp:// deep link, a QR code, or an equivalent https link —
// carries: a Request Object by reference (JAR, RFC 9101 §5.2), which
// HAIP 1.0 §5.1 requires.
type AuthorizationRequestLink struct {
	// ClientID is the Verifier's client_id, e.g. "x509_hash:...". Pass
	// it with the fetched Request Object to FetchAuthorizationRequest or
	// ParseAuthorizationRequest, which check the two agree.
	ClientID string

	// RequestURI is where to fetch the Request Object.
	RequestURI string

	// RequestURIMethod is RequestURIMethodGet, or RequestURIMethodPost
	// when the Verifier accepts a POST with a wallet_nonce (§5.10). A
	// Wallet that doesn't support POST MAY fetch with GET anyway (§5).
	RequestURIMethod string
}

// ParseAuthorizationRequestLink reads link's client_id, request_uri and
// request_uri_method query parameters. The link's scheme and host are
// not checked, since Wallets are invoked through custom schemes and
// https links alike. A request passed by value ("request") or as plain
// parameters is refused: only request_uri is supported.
func ParseAuthorizationRequestLink(link string) (AuthorizationRequestLink, error) {
	u, err := url.Parse(link)
	if err != nil {
		return AuthorizationRequestLink{}, fmt.Errorf("wallet: parse authorization request link: %w", err)
	}
	q := u.Query()
	parsed := AuthorizationRequestLink{
		ClientID: q.Get("client_id"), RequestURI: q.Get("request_uri"), RequestURIMethod: q.Get("request_uri_method"),
	}
	switch {
	case parsed.ClientID == "":
		return AuthorizationRequestLink{}, errors.New("wallet: parse authorization request link: client_id is required")
	case parsed.RequestURI == "" && q.Has("request"):
		return AuthorizationRequestLink{}, errors.New("wallet: parse authorization request link: a Request Object by value isn't supported, only request_uri")
	case parsed.RequestURI == "":
		return AuthorizationRequestLink{}, errors.New("wallet: parse authorization request link: request_uri is required")
	}
	if ru, err := url.Parse(parsed.RequestURI); err != nil || !ru.IsAbs() || ru.Host == "" {
		return AuthorizationRequestLink{}, fmt.Errorf("wallet: parse authorization request link: request_uri %q isn't an absolute URL", parsed.RequestURI)
	}
	switch parsed.RequestURIMethod {
	case "":
		parsed.RequestURIMethod = RequestURIMethodGet
	case RequestURIMethodGet, RequestURIMethodPost:
	default:
		// OID4VP §5.10 / Appendix E.3.2: invalid_request_uri_method.
		return AuthorizationRequestLink{}, fmt.Errorf("wallet: parse authorization request link: request_uri_method %q is neither get nor post", parsed.RequestURIMethod)
	}
	return parsed, nil
}
