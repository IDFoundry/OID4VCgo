package walletflow

import (
	"errors"
	"fmt"
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
)

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
