package walletflow

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/idfoundry/oid4vcgo/internal/displaytext"
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
	// ErrRefreshInProgress is wrapped by Wallet.RefreshCredential when
	// another Wallet sharing the GrantStore — another process — is
	// redeeming the credential's refresh grant: a refresh token is never
	// redeemed twice at once. Try again once that refresh is done.
	ErrRefreshInProgress = errors.New("walletflow: another wallet is refreshing with this refresh grant")
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
	// ErrTxCodeRefused is wrapped by Issuance.RedeemPreAuthorizedCode
	// when the token endpoint refuses a PIN-protected code with
	// invalid_grant. OpenID4VCI §6.3 answers a wrong PIN and an expired
	// or already used code alike, so it means either: ask the holder for
	// the PIN again, which the same Issuance accepts until the issuer's
	// attempt limit ends the code, and offer to start over from a new
	// offer if it keeps failing.
	ErrTxCodeRefused = errors.New("walletflow: the issuer refused the PIN, or the code has expired or been used")
	// ErrCredentialChanged is wrapped by Presentation.Respond (and the
	// mdoc presentations' Respond) when a selected credential was
	// replaced — refreshed, say — after the presentation started, so
	// what would be sent isn't what the holder was shown. Nothing is
	// sent. Start the presentation again to show the holder the new
	// credential.
	ErrCredentialChanged = errors.New("walletflow: the credential changed after the holder was shown it")

	// ErrMalformedRequest is wrapped for a Digital Credentials API
	// request (StartDCAPIPresentation, StartMdocPresentation) that can't
	// be parsed: what the platform handed over, not a service's answer.
	ErrMalformedRequest = errors.New("walletflow: the request is malformed")
	// ErrNotConfigured is wrapped where the Wallet lacks what a call
	// needs, which New doesn't require of every wallet: Config.IssuerRoots
	// or Config.RedirectURI to receive credentials, Config.VerifierTrust
	// to present them, or Dependencies.Provider and Config.ClientID under
	// ProfileHAIP. It's the integration to fix, not a service's answer.
	ErrNotConfigured = errors.New("walletflow: the wallet isn't configured for this")
	// ErrRequestRefused is wrapped, in a *RequestRefusedError, by
	// StartPresentation and StartDCAPIPresentation for an authentic
	// request the wallet must refuse: transaction_data it doesn't
	// support (OpenID4VP §8.4: "it MUST return an error"), an origin
	// outside a signed request's expected_origins (Appendix A.2), or a
	// parameter OpenID4VP forbids. The Verifier is told, as OpenID4VP
	// requires: see RequestRefusedError.
	ErrRequestRefused = errors.New("walletflow: the wallet refuses the request")
	// ErrUntrustedVerifier is wallet.ErrUntrustedVerifier, wrapped by
	// StartPresentation for a request from a Verifier VerifierTrust
	// doesn't accept, and by StartMdocPresentation, under
	// Config.RequireTrustedMdocReader, for one no recognized reader
	// signed.
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

// cleanText fits untrusted text for an error as displaytext.Shorten
// does, cut to maxErrorTextRunes: control characters and line or
// paragraph separators become spaces and invisible format characters
// go, so it can't forge log or screen lines, or flood a screen.
func cleanText(text string) string {
	return displaytext.Shorten(text, maxErrorTextRunes)
}

// RequestRefusedError is an authentic request the wallet refused, and
// the error it returned to the Verifier (OpenID4VP §8.5). For a
// redirect request, the error response was sent to the request's
// response_uri before StartPresentation returned; for a Digital
// Credentials API request, DCAPIResponse is the error to hand back to
// the platform, as for Presented.DCAPIResponse. Show the holder that
// the request was refused, not that the wallet failed.
type RequestRefusedError struct {
	// Code and Description are the error response's error and
	// error_description: invalid_transaction_data, invalid_request, and
	// so on.
	Code        string
	Description string

	// RedirectURI is where the Verifier asked to take the holder after
	// receiving the error (same-device), "" for none.
	RedirectURI string

	// DCAPIResponse is a DC API request's error response.
	DCAPIResponse []byte

	// sendErr is why the error response couldn't be sent: the Verifier
	// may not have been told.
	sendErr error
}

func (e *RequestRefusedError) Error() string {
	msg := "walletflow: the wallet refuses the request: " + e.Code
	if e.Description != "" {
		msg += ": " + e.Description
	}
	if e.sendErr != nil {
		msg += " (the Verifier wasn't told: " + e.sendErr.Error() + ")"
	}
	return msg
}

// Unwrap is ErrRequestRefused, and why the error response couldn't be
// sent, if it couldn't.
func (e *RequestRefusedError) Unwrap() []error {
	if e.sendErr != nil {
		return []error{ErrRequestRefused, e.sendErr}
	}
	return []error{ErrRequestRefused}
}
