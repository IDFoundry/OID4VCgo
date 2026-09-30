// Package fapiresource adapts a fapigo/resource.Verifier to
// issuer.AccessTokenVerifier, for an Issuer whose access tokens come
// from a fapigo/server Authorization Server (or its own
// ExchangePreAuthorizedCode). It's a separate package so that issuer
// itself doesn't depend on fapigo/resource.
package fapiresource

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// Verifier is an issuer.AccessTokenVerifier backed by a
// fapigo/resource.Verifier.
type Verifier struct {
	resource *resource.Verifier
}

// New returns a Verifier that checks access tokens with v.
func New(v *resource.Verifier) (*Verifier, error) {
	if v == nil {
		return nil, errors.New("fapiresource: resource verifier is required")
	}
	return &Verifier{resource: v}, nil
}

// Verify implements issuer.AccessTokenVerifier. The Grant's
// ClientIdentity is the token's client_id, or issuer.NoClientIdentity{}
// for a token that names no client — such as one
// ExchangePreAuthorizedCode minted for an anonymous redemption — so
// nothing is bound to a client for that request, and a deferred
// transaction bound to a client refuses it. Its AuthorizationDetails
// are the token's authorization_details claim; a malformed one fails
// verification.
func (v *Verifier) Verify(r *http.Request, endpoint *url.URL) (issuer.Grant, error) {
	authCtx, err := v.resource.Verify(r.Context(), resource.VerifyRequest{
		Method: r.Method, URL: endpoint, Authorization: r.Header.Get("Authorization"),
		DPoPProofs: resource.DPoPProofsFromHTTP(r), PeerCertificate: resource.PeerCertificateFromHTTP(r),
	})
	if err != nil {
		return issuer.Grant{}, err
	}
	var client issuer.ClientIdentity = issuer.NoClientIdentity{}
	if authCtx.ClientID != "" {
		client = issuer.KnownClientID(authCtx.ClientID)
	}
	grant := issuer.Grant{
		Subject:    authCtx.Subject,
		DPoPNonce:  authCtx.NextDPoPNonce,
		Authorized: issuer.AuthorizedRequest{ClientIdentity: client, Scopes: authCtx.Scopes},
	}
	if raw, ok := authCtx.Claims["authorization_details"]; ok {
		if err := json.Unmarshal(raw, &grant.Authorized.AuthorizationDetails); err != nil {
			return issuer.Grant{}, resource.NewError(resource.ErrorInvalidToken, http.StatusUnauthorized,
				"access token authorization_details is malformed")
		}
	}
	return grant, nil
}

// WriteError implements issuer.AccessTokenVerifier with
// resource.WriteError.
func (v *Verifier) WriteError(w http.ResponseWriter, err error) {
	resource.WriteError(w, err)
}

var _ issuer.AccessTokenVerifier = (*Verifier)(nil)
