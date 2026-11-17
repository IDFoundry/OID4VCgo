// Package fapiresource adapts a fapigo/resource.Verifier to
// issuer.AccessTokenVerifier, for an Issuer whose access tokens come
// from a fapigo/server Authorization Server (or its own
// ExchangePreAuthorizedCode). It's a separate package so that issuer
// itself doesn't depend on fapigo/resource.
//
// When the Authorization Server runs in the same process, build the
// resource.Verifier with fapigo/serverresource.NewVerifier from the
// server's own Config and Dependencies: it checks revocation against
// the store the server revokes into, so a token the server revokes
// stops working at the Credential Endpoint too, and matches its
// access-token format.
//
// Build one resource.Verifier per Credential Issuer, with
// serverresource.Options.Resource set to that issuer's Config.Issuer,
// so only a token issued for it (requested with it as its RFC 8707
// resource) is accepted. Without Options.Resource, the verifier accepts
// tokens addressed to the Authorization Server itself, which is safe
// only when the Authorization Server serves this one Credential Issuer:
// one serving several issues each one's tokens alike, and a token
// issued for one would be taken for its own by another, which would
// look its own holder up by the other issuer's subject. The Grant
// carries the token's audience either way (issuer.AuthorizedRequest.Audience),
// and the Issuer refuses one that doesn't name it unless
// issuer.Config.AcceptedAccessTokenAudiences lists the Authorization
// Server.
package fapiresource

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/idfoundry/fapigo/resource"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
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
// verification. Its Audience is the token's audience, never nil, so the
// Issuer checks it names this Credential Issuer.
//
// Only an end user's token is accepted (resource.SubjectEndUser): a
// client credentials token's subject is the client's own client_id,
// which a client choosing its own (through OpenID Federation, say)
// could make equal to a holder's subject, and the Grant's Subject
// decides whose Credential is issued. It's refused as 403
// insufficient_scope.
func (v *Verifier) Verify(r *http.Request, endpoint *url.URL) (issuer.Grant, error) {
	req := resource.VerifyRequestFromHTTP(r)
	req.URL = endpoint
	authCtx, err := v.resource.Verify(r.Context(), req)
	if err != nil {
		return issuer.Grant{}, err
	}
	if authCtx.SubjectKind != resource.SubjectEndUser {
		return issuer.Grant{}, resource.NewInsufficientScopeError(authCtx, "a Credential needs an end user's access token")
	}
	// Without the internal subject (a resource verifier resolving only
	// pairwise client subjects), every holder's Grant would carry the
	// same empty Subject: their Prepare lookups, deferred transactions
	// and notification_ids would all be one holder's. That's the
	// deployment's configuration, not the token's fault.
	if authCtx.InternalSubject == "" {
		return issuer.Grant{}, errors.New("fapiresource: the access token's internal subject isn't resolved (configure the resource verifier to resolve internal subjects): holders can't be told apart")
	}
	var client issuer.ClientIdentity = issuer.NoClientIdentity{}
	if authCtx.ClientID != "" {
		client = issuer.KnownClientID(authCtx.ClientID)
	}
	grant := issuer.Grant{
		Subject:   authCtx.InternalSubject,
		DPoPNonce: authCtx.NextDPoPNonce,
		Authorized: issuer.AuthorizedRequest{
			ClientIdentity: client, Subject: authCtx.InternalSubject, Scopes: authCtx.Scopes,
			// Never nil, so the Issuer always checks it.
			Audience: append([]string{}, authCtx.Audience...),
		},
	}
	if raw, ok := authCtx.Claims["authorization_details"]; ok {
		if err := strictjson.Unmarshal(raw, &grant.Authorized.AuthorizationDetails); err != nil {
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
