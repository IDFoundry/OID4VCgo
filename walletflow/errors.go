package walletflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"unicode"

	"github.com/idfoundry/oid4vcgo/wallet"
)

var (
	// ErrNotFound is wrapped by a KeyStore or CredentialStore lookup of
	// something it doesn't hold.
	ErrNotFound = errors.New("walletflow: not found")
	// ErrWrongStep is returned for a session method called out of turn:
	// a step already taken, one the offer's grant doesn't have, or any
	// call after Close.
	ErrWrongStep = errors.New("walletflow: not the session's next step")
	// ErrCredentialDenied is returned for a deferred credential the
	// issuer refused (OpenID4VCI 1.0 §9.3, credential_request_denied).
	ErrCredentialDenied = errors.New("walletflow: the issuer denied the credential")
	// ErrNoMatchingCredential is returned by Presentation.Respond when
	// the wallet holds nothing that answers the request.
	ErrNoMatchingCredential = errors.New("walletflow: no held credential answers the request")
	// ErrReissueRequired is wrapped by Wallet.RefreshCredential when a
	// credential can't be refreshed: it came without a refresh token, or
	// the Authorization Server no longer accepts it. Receive it again
	// from a new Credential Offer.
	ErrReissueRequired = errors.New("walletflow: the credential can't be refreshed: receive it again")
	// ErrDeliveryUnknown is wrapped by Presentation.Respond when sending
	// the response failed in a way that leaves it unknown whether the
	// Verifier received it — the connection failed or timed out, or the
	// Verifier answered with a server error. The Presentation is then
	// answered: sending again could present twice.
	ErrDeliveryUnknown = errors.New("walletflow: the response may or may not have reached the verifier")
	// ErrLinkable is wrapped by Presentation.Respond when a selected
	// credential's copy would now be one another Verifier has seen,
	// though it wasn't when the presentation started (Linkable said
	// false): another presentation used the last unused copy meanwhile.
	// Nothing is sent. Check Linkable again — it now says true — and let
	// the holder decide, or refresh the credential first.
	ErrLinkable = errors.New("walletflow: a copy another verifier has seen would now be presented")
	// ErrUntrustedVerifier is wallet.ErrUntrustedVerifier, wrapped by
	// StartPresentation for a request from a Verifier VerifierTrust
	// doesn't accept.
	ErrUntrustedVerifier = wallet.ErrUntrustedVerifier
)

// deliveryUnknown reports whether err, from sending a direct_post
// response, leaves it unknown whether the Verifier received it: a
// transport failure or a server error, rather than the Verifier's
// refusal.
func deliveryUnknown(err error) bool {
	var rejected *wallet.DirectPostRejectedError
	if errors.As(err, &rejected) {
		return rejected.StatusCode >= http.StatusInternalServerError
	}
	var urlErr *url.Error
	var netErr net.Error
	return errors.As(err, &urlErr) || errors.As(err, &netErr) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// AuthorizationDeniedError is returned by Issuance.CompleteAuthorization
// when the Authorization Server answered with an error, such as the
// holder declining (access_denied).
type AuthorizationDeniedError struct {
	Code        string
	Description string
}

func (e *AuthorizationDeniedError) Error() string {
	if e.Description == "" {
		return fmt.Sprintf("walletflow: authorization denied: %s", e.Code)
	}
	return fmt.Sprintf("walletflow: authorization denied: %s: %s", e.Code, e.Description)
}

// maxErrorTextRunes bounds text from an issuer, Authorization Server or
// callback that walletflow puts in an error.
const maxErrorTextRunes = 256

// cleanText drops control characters from untrusted text and cuts it to
// maxErrorTextRunes, so it can't forge log lines or flood a screen.
func cleanText(text string) string {
	var b strings.Builder
	n := 0
	for _, r := range text {
		if unicode.IsControl(r) {
			continue
		}
		if n == maxErrorTextRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}
