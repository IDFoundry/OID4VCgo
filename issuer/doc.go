// Package issuer implements the OID4VCI 1.0 Credential Issuer role
// (the server side): the Nonce Endpoint (§7), Credential Issuer
// Metadata (§12.2), the Credential Endpoint (§8), and — as they land —
// the Credential Offer, Deferred Credential and Notification Endpoints.
//
// This package doesn't verify the access token authorizing a Credential
// Request itself: that needs full HTTP request context (method, URL,
// DPoP proof or mTLS certificate) that has nothing to do with
// Credential Request/Response protocol logic — ordinarily
// fapigo/resource.Verifier.Verify, called by the caller before
// RequestCredential, its result adapted into AuthorizedRequest. This
// package never reaches into fapigo's internal packages; see
// ARCHITECTURE.md's "Relationship to FAPIgo" for why that's a hard
// boundary, not a style choice.
//
// # Status
//
// The Nonce Endpoint, a Metadata shape covering SD-JWT VC and mso_mdoc
// issuance, and the Credential Endpoint (both formats, both the jwt and
// attestation proof types, immediate issuance with batch support) exist
// so far. See CredentialRequest's own doc comment for exactly what the
// Credential Endpoint doesn't implement yet (credential_identifier,
// di_vp, kid/x5c-based key resolution, request/response encryption,
// deferred issuance, unbound credentials), and ARCHITECTURE.md for the
// planned shape of what's still missing at the package level (Credential
// Offer, Deferred Credential, Notification).
package issuer
