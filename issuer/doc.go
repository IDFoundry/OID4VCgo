// Package issuer implements the OID4VCI 1.0 Credential Issuer role
// (the server side): the Nonce Endpoint (§7), Credential Issuer
// Metadata (§12.2), the Credential Endpoint (§8), the Credential Offer
// (§4), the Deferred Credential Endpoint (§9), and the Notification
// Endpoint (§11).
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
// issuance, the Credential Endpoint (both formats, both the jwt and
// attestation proof types, immediate issuance with batch support),
// Credential Offer construction/dereferencing (§4: both by value and
// by reference), the Deferred Credential Endpoint's own polling
// protocol (§9), and the Notification Endpoint (§11) all exist now.
// See CredentialRequest's own doc comment for exactly what the
// Credential Endpoint doesn't implement yet (credential_identifier,
// di_vp, kid/x5c-based key resolution, request/response encryption,
// unbound credentials — and note it never defers issuance itself),
// CredentialOffer's own doc comment for what the Credential Offer
// doesn't cover yet (issuing/redeeming a pre-authorized_code or
// issuer_state — this package treats both as caller-supplied, since
// there is no Token/Authorization Endpoint yet to own that),
// DeferredTransactionRecord's own doc comment for why this package
// never creates or resolves a Deferred Issuance transaction itself,
// and NotificationHandler's own doc comment for why reacting to a
// Notification Request's event is entirely the caller's business
// logic. ARCHITECTURE.md describes what's still missing beyond this
// package's own endpoints (Authorization/Token Endpoint machinery,
// via fapigo/server, once this repo needs it).
package issuer
