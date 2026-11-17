package issuer

import (
	"errors"
	"fmt"
	"slices"
)

// This file is mostly documentation: its one function,
// AuthorizationResources, is the consent step's resource decision (see
// "Restricting access tokens to this Credential Issuer" below). See the
// package doc comment's own "Status" section for why: this
// package deliberately doesn't wrap fapigo/server's own Authorization/
// Token Endpoints (mirrors wallet's own "never wraps fapigo/client's
// BeginAuthorization/ExchangeCode" stance — see wallet/authorization.go's
// doc comment). A deployment that wants its Credential Issuer to also
// act as the FAPI 2.0 Authorization Server OID4VCI 1.0 §5/HAIP 1.0 §4
// describe constructs and drives a *fapigo/server.Server directly,
// using its own public API exactly as any other fapigo/server caller
// would. What follows is the integration recipe for doing that
// alongside an *Issuer, not new production code.
//
// # Registering issuer_state
//
// OID4VCI 1.0 §4.1.1's own issuer_state authorization parameter should
// be registered in the Authorization Server's own
// server.Config.Extensions (fapigo/extension.Registry) — an
// unregistered authorization request parameter no longer fails the
// whole Pushed Authorization Request (RFC 6749 §3.1/RFC 9126 §2.1
// require tolerating one, fixed in FAPIgo's own
// fix!: ignore unrecognized authorization request parameters at
// PAR/CIBA), but fapigo/extension.Registry.Parse still deletes an
// unregistered parameter's value as it goes rather than forwarding it
// anywhere — so skipping registration no longer produces a loud
// rejection at PAR time, it silently drops issuer_state instead,
// which is a worse failure mode to discover later, not a better one to
// skip. Use oid4vci.IssuerStateExtension, exported specifically so
// both sides of this handshake share one canonical
// extension.Definition[string] value rather than risking two
// independently-declared copies drifting apart:
//
//	extensions, err := extension.NewRegistry(oid4vci.IssuerStateExtension /* , any others this deployment needs */)
//	cfg := server.Config{ /* ... */ Extensions: extensions}
//
// haip.RecommendedAuthorizationServerConfig returns a server.Config
// with this registry and the rest of HAIP's Authorization Server
// settings already set.
//
// wallet.BuildAuthorizationRequest already attaches issuer_state to the
// Wallet's own outbound Authorization Request using this exact
// Definition (via fapigo/extension.Set) whenever a resolved Credential
// Offer's authorization_code grant carries one (§4.1.1's own MUST).
//
// # Reading issuer_state at the consent step
//
// Once registered, issuer_state is readable at the interaction step:
// (*server.Server).BeginAuthorization's InteractionRequired.Interaction
// (a server.InteractionRequest) carries the request's registered
// extension values in Extensions, whether the Wallet sent them as
// plain PAR parameters or inside a signed request object:
//
//	state, ok := extension.Get(action.Interaction.Extensions, oid4vci.IssuerStateExtension)
//
// That's where a Credential Issuer correlates the authorization back to
// the Credential Offer that started it — to show the resource owner
// what's being issued, or to look up the pending issuance — with no
// need to capture the value off the PAR request itself.
//
// The Wallet sends whatever issuer_state its offer carried, and a
// Credential Offer can reach anyone, so issuer_state only says which
// offer: it doesn't authenticate the End-User. Authenticate them at the
// consent step and check they're the one the offer was made for before
// issuing their Credential, and make issuer_state an unguessable value
// (CreateCredentialOffer doesn't choose it).
//
// BeginAuthorization returns the InteractionRequest once, and the
// consent step needs it back, with the handle, when the holder submits.
// fapigo/server/interactioncookie carries both in one AES-256-GCM-sealed
// cookie on the browser that began the authorization: Set it with
// BeginAuthorization's InteractionRequired before rendering the consent
// page, put the tag Set returns in the form (interactioncookie.FormField),
// Read it with that tag when the form comes back (issuer_state is in the
// restored request's Extensions, as above), and Clear it once
// CompleteAuthorization has run. The tag stops a form from a page whose
// interaction another tab replaced from completing the replacement. Sealed, the request can't be altered —
// which matters, because issuer_state decides whose Credential is
// issued, and CompleteAuthorization checks only the grant's scopes
// against the request the server stored — and the approval can only be
// submitted from that browser. Any instance holding the cookie's key can
// finish the interaction. The cookie isn't a CSRF defence: refuse a
// consent form posted from another origin too. If you keep the state
// elsewhere instead (InteractionRequest.MarshalText, restored with
// server.ParseInteractionRequest and server.ParseInteractionHandle),
// keep it where only your application can write it, for the same
// reason. examples/passport-vdc's issuer uses the cookie.
//
// # Restricting access tokens to this Credential Issuer
//
// An Authorization Server serving several Credential Issuers issues
// each one's tokens with the same "iss", and a Subject that's
// meaningful to one issuer only, so a token must be addressed to the
// Credential Issuer whose consent step authorized it. The Wallet's RFC
// 8707 resource chooses the token's audience. List each Credential
// Issuer the Authorization Server serves in its
// server.Config.Resources, and have each one's consent step grant only
// that Credential Issuer, with AuthorizationResources:
//
//	resources, err := iss.AuthorizationResources(action.Interaction.Resources)
//	if err != nil {
//		result = server.Deny("the request names another resource")
//	} else {
//		result = server.Authorize(subject, authCtx, server.GrantedAuthorization{
//			Scope: granted, Resources: resources,
//		})
//	}
//
// Leaving GrantedAuthorization.Resources nil grants every resource the
// request named: a Wallet whose request names another Credential
// Issuer, and whose consent step here signs in this Credential Issuer's
// user-42, would get a token the other one takes for its own user-42.
// Narrowing the grant to this Credential Issuer is refused when the
// request didn't name it, so such a request must be denied. Verify the
// tokens at the Credential Endpoint for the same identifier
// (fapigo/serverresource's Options.Resource), and restrict the
// pre-authorized code grant's tokens to it too
// (RedeemedPreAuthorizedCode.Resource).
//
// # Credential Endpoint access tokens
//
// A Wallet presents whatever access token the paired Authorization
// Server issued (via (*server.Server).ExchangeAuthorizationCode or
// RefreshAccessToken) back to the Credential Endpoint. Verifying that
// presented token is fapigo/resource.Verifier.Verify's own job, not
// this package's or fapigo/server's — see AuthorizedRequest's own doc
// comment for how its result is adapted into RequestCredential's own
// input. fapigo/server and fapigo/resource are independent fapigo
// packages for exactly this reason: issuing a token and verifying one
// presented later are different roles with different request-context
// needs (RFC 9449 DPoP proof/mTLS certificate at verification time),
// the same client/server split this repo's own ARCHITECTURE.md
// describes for FAPIgo generally.
//
// # Refreshing credentials
//
// A refresh token (OpenID4VCI 1.0 §13.5) lets a Wallet get fresh
// credentials — a new batch, for new holder keys — with no holder
// present. Issue one only when the issuer will issue again from data it
// keeps, and:
//   - Keep the token's lifetime (server.Config.Limits.
//     RefreshTokenLifetime) no longer than the data is kept, and delete
//     the data when the grant ends.
//   - Bind it to the Wallet instance: with Wallet Attestation,
//     fapigo/server binds it to the attestation's key, so another
//     installation of the same wallet can't redeem it.
//   - Serve token revocation (RFC 7009, server.Server.RevokeToken), so a
//     Wallet deleting the credential ends the grant; RevokeToken reports
//     which grant ended, to delete what was kept for it.
//   - Bound how often one grant is redeemed: each refresh takes new
//     status list indices, which are shared by every credential.
//
// For the pre-authorized code grant, server.Server.IssueRefreshToken
// issues one for ExchangePreAuthorizedCodeResult.RefreshToken.

// ErrResourceNotThisIssuer is wrapped by AuthorizationResources' error:
// the authorization request named RFC 8707 resources, none of them this
// Credential Issuer, or it named none where its token would then be
// addressed to an Authorization Server this Credential Issuer doesn't
// accept.
var ErrResourceNotThisIssuer = errors.New("issuer: the authorization request doesn't name this Credential Issuer as its resource")

// AuthorizationResources is the RFC 8707 resources the consent step of
// an authorization for this Credential Issuer grants (fapigo/server's
// GrantedAuthorization.Resources), from the ones the request named
// (InteractionRequest.Resources): exactly Config.Issuer, when requested
// includes it. When requested names resources but not Config.Issuer, it
// returns an error wrapping ErrResourceNotThisIssuer, and the consent
// step must Deny the request: granting it would give the Wallet a token
// for another resource, under a Subject this Credential Issuer's
// consent step authenticated.
//
// A request that named no resource gets a token addressed to the
// Authorization Server itself. It's granted (nil, nil) when this
// Credential Issuer takes such a token: when it's its own Authorization
// Server (Config.AuthorizationServers is empty, so the Authorization
// Server's identifier is Config.Issuer), or when
// Config.AcceptedAccessTokenAudiences lists one. Otherwise it's refused
// as a foreign resource is: OpenID4VCI 1.0 §5.1.2 has a Wallet send the
// Credential Issuer's identifier as its resource when the metadata
// lists authorization_servers.
//
// See "Restricting access tokens to this Credential Issuer" above.
func (iss *Issuer) AuthorizationResources(requested []string) ([]string, error) {
	own := iss.cfg.Issuer.String()
	switch {
	case slices.Contains(requested, own):
		return []string{own}, nil
	case len(requested) > 0:
		return nil, fmt.Errorf("%w: it names %q", ErrResourceNotThisIssuer, requested)
	case len(iss.cfg.AuthorizationServers) == 0 || len(iss.cfg.AcceptedAccessTokenAudiences) > 0:
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: it names none, and a token addressed to the Authorization Server isn't accepted here (config.accepted_access_token_audiences)", ErrResourceNotThisIssuer)
	}
}
