// Package wallet implements the OID4VCI 1.0 Wallet role (the client
// side): resolving a Credential Offer (§4), generating jwt-type key
// proofs of possession (Appendix F.1), and driving the Credential
// Endpoint (§8) and Nonce Endpoint (§7). It is built on fapigo/client
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
// # Status
//
// ResolveCredentialOffer, RequestNonce, GenerateProof,
// RequestCredential, and BuildAuthorizationRequest exist so far. This
// package does not yet cover:
//
//   - The pre-authorized_code Flow: a plain Token Endpoint POST for
//     grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code,
//     entirely outside fapigo/client's own scope (it's OID4VCI-specific,
//     not a FAPI 2.0 or base OAuth 2.0 grant) — and, unlike the
//     Authorization Code Flow above, getting it DPoP-sender-constrained
//     per HAIP §4 would require this package to build its own RFC 9449
//     DPoP proof, since fapigo/client exposes no generic DPoP-signed
//     Token Request primitive for a grant type it doesn't itself
//     implement. Deferred pending a decision on that tradeoff.
//   - The Deferred Credential Endpoint (§9) and Notification Endpoint
//     (§11) — polling a transaction_id and reporting an issuance
//     outcome are both separate, later work.
//   - A Credential Response that itself defers issuance (§8.3's own
//     HTTP 202, transaction_id/interval case) — RequestCredential
//     only handles the immediate HTTP 200 case.
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
