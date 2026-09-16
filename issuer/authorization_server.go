package issuer

// This file is documentation only — no exported types or functions.
// See the package doc comment's own "Status" section for why: this
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
// wallet.BuildAuthorizationRequest already attaches issuer_state to the
// Wallet's own outbound Authorization Request using this exact
// Definition (via fapigo/extension.Set) whenever a resolved Credential
// Offer's authorization_code grant carries one (§4.1.1's own MUST).
//
// # issuer_state does not resurface through BeginAuthorization
//
// This is the one genuinely non-obvious part of the recipe: once
// fapigo/server accepts issuer_state at the Pushed Authorization
// Request step, it is NOT surfaced back out through
// (*server.Server).BeginAuthorization's own InteractionRequired.Interaction
// (a server.InteractionRequest) — that type exposes only ClientID,
// Scope, Hints and AuthorizationDetails (Rich Authorization Requests
// have their own separate, dedicated path); a generic
// extension.Definition-backed parameter resurfaces later only as a
// token claim, and only when its own ReturnInTokenClaims is true — not
// what issuer_state needs here, since correlating the authorization
// flow back to the originating Credential Offer is a consent-time
// concern, not a token-claims one.
//
// So a deployment that needs issuer_state for consent-time correlation
// (e.g. to show the resource owner which Credential Offer initiated
// this flow, or to pre-select what's being requested) must capture it
// itself, directly off the incoming Authorization Request/PAR HTTP
// call, before or independently of handing off to
// (*server.Server).PushAuthorizationRequest/BeginAuthorization — the
// same "this package doesn't own the HTTP handler or consent UI"
// boundary RequestCredential's own AuthorizedRequest parameter already
// draws for token verification.
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
