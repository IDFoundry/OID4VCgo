// Package wallet implements the OID4VCI 1.0 Wallet role (the client
// side): resolving a Credential Offer (§4), generating jwt-type key
// proofs of possession (Appendix F.1), and driving the Credential
// Endpoint (§8) and Nonce Endpoint (§7). It is built on fapigo/client
// for everything OAuth 2.0/FAPI 2.0-level — this package never
// reimplements PAR, DPoP, or client authentication itself; see
// ProtectedResourceClient's own doc comment for the boundary.
//
// # Status
//
// ResolveCredentialOffer, RequestNonce, GenerateProof and
// RequestCredential exist so far — resolving a Credential Offer and
// completing one immediate-issuance Credential Request/Response
// round trip against an issuer, once a caller has already obtained an
// access token some other way. This package does not yet cover:
//
//   - Acquiring that access token in the first place — neither the
//     Authorization Code Flow (drive fapigo/client's own
//     BeginAuthorization/ExchangeCode directly) nor the
//     pre-authorized_code Flow (a plain Token Endpoint POST this
//     package doesn't build yet).
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
