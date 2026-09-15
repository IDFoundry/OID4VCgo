// Package wallet implements the OID4VCI 1.0 Wallet role (the client
// side): resolving a Credential Offer (§4), generating jwt-type key
// proofs of possession (Appendix F.1), and driving the Credential
// Endpoint (§8), Nonce Endpoint (§7), Deferred Credential Endpoint
// (§9) and Notification Endpoint (§11). It is built on fapigo/client
// for everything OAuth 2.0/FAPI 2.0-level — this package never
// reimplements PAR, DPoP, or client authentication itself; see
// ProtectedResourceClient's own doc comment for the boundary.
//
// This package deliberately doesn't wrap fapigo/client's own
// BeginAuthorization, HandleAuthorizationResponse or ExchangeCode —
// driving the Authorization Code Flow, and turning its result into a
// sender-constrained client via (*client.Client).ProtectedResource, is
// squarely fapigo/client's own public API, the same way issuer never
// wraps fapigo/server's Authorization/Token Endpoints.
// BuildAuthorizationRequest exists only because translating a resolved
// Credential Offer's own authorization_code grant (its issuer_state)
// into that call's own request shape is genuinely OID4VCI-specific
// logic fapigo/client has no reason to know about; calling
// BeginAuthorization itself with the result, and everything after it,
// is on the caller.
//
// fapigo/client's own defaults already satisfy HAIP 1.0 §4's
// Authorization Code Flow requirements without any override: Profile
// ProfileFAPISecurity always uses PAR and PKCE with S256; its
// SenderConstrain zero value is already SenderConstrainDPoP; and
// client.RecommendedAlgorithms already picks ES256 for
// ClientAuthentication/DPoP, matching HAIP §7's own minimum. The one
// requirement fapigo/client cannot satisfy yet is HAIP §4.4.1's Wallet
// Attestation client authentication: storage.ClientAuthMethodAttestation
// itself exists (added so fapigo/server can verify a Wallet Attestation
// — see ARCHITECTURE.md's "Relationship to FAPIgo"), but fapigo/client
// has no logic of its own to construct or send the Client Attestation +
// PoP JWT pair when Config.ClientAuthMethod names it — only the server
// side knows how to verify one so far. A HAIP-profile wallet built on
// today's fapigo/client must use ClientAuthMethodPrivateKeyJWT instead —
// FAPI 2.0-compliant, but not yet what HAIP specifically asks for.
//
// RequestPreAuthorizedCodeToken implements the Pre-Authorized Code
// Flow's own Token Request/Response (§6.1/§6.2) directly, rather than
// through fapigo/client: that grant type
// (urn:ietf:params:oauth:grant-type:pre-authorized_code) is entirely
// outside fapigo/client's own scope (it's OID4VCI-specific, not a FAPI
// 2.0 or base OAuth 2.0 grant), and fapigo/client exposes no generic
// DPoP-signed Token Request primitive for a grant type it doesn't
// itself implement. GenerateDPoPProof and DPoPAccessTokenHash build the
// RFC 9449 DPoP proof this needs, reusing the same internal/jose and
// internal/jwk primitives GenerateProof already relies on for key
// proofs — see GenerateDPoPProof's own doc comment for why it's
// exported: this package builds the Token Request's own proof, but not
// a full sender-constrained resource client for the token it returns,
// so a caller needs GenerateDPoPProof to build that client itself.
// Client authentication isn't supported for this flow either (§6.1
// makes it OPTIONAL, and Wallet Attestation client auth isn't buildable
// yet — see this comment's own note on storage.ClientAuthMethodAttestation
// above), and neither is authorization_details, matching this package's
// own credential_configuration_id-only scope.
//
// # Status
//
// ResolveCredentialOffer, RequestNonce, GenerateProof,
// RequestCredential, BuildAuthorizationRequest,
// RequestDeferredCredential, RequestNotification,
// RequestPreAuthorizedCodeToken, GenerateDPoPProof and
// DPoPAccessTokenHash exist so far. This package does not yet cover:
//
//   - di_vp and attestation proof types (only jwt is supported), and
//     kid/x5c-conveyed binding keys (only jwk, matching issuer's own
//     scope).
//   - Request/response encryption (§10).
//
// A Wallet MUST treat a Credential Offer's contents as untrustworthy
// (§13.5: unauthenticated, integrity-unprotected) — ResolveCredentialOffer
// only checks structural well-formedness (oid4vci.CredentialOffer.Validate),
// never who sent it.
package wallet
