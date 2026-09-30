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
// BeginAuthorization returns the InteractionRequest once. When the
// consent step may run on another instance, store its encoding
// (InteractionRequest.MarshalText) under the handle's String() — in a
// shared session store, or a cookie you sign — and restore it there
// with server.ParseInteractionRequest and server.ParseInteractionHandle;
// issuer_state comes back with it, read with extension.Get as above.
// CompleteAuthorization checks the grant against the request the server
// itself stored, so a tampered copy can't widen it, but keep it where
// only your application can write it so the consent page shows what
// was actually asked.
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
