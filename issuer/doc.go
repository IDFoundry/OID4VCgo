// Package issuer implements the OID4VCI 1.0 Credential Issuer role
// (the server side): the Nonce Endpoint (§7), Credential Issuer
// Metadata (§12.2), the Credential Endpoint (§8), the Credential Offer
// (§4), the Deferred Credential Endpoint (§9), the Notification
// Endpoint (§11), and the Pre-Authorized Code Flow's own Token
// Request/Response (§6.1/§6.2).
//
// This package doesn't verify the access token authorizing a Credential
// Request itself: that needs full HTTP request context (method, URL,
// DPoP proof or mTLS certificate) that has nothing to do with
// Credential Request/Response protocol logic — ordinarily
// fapigo/resource.Verifier.Verify, called by the caller before
// RequestCredential, its result adapted into AuthorizedRequest; see
// resource_verifier.go for the worked recipe. This package never
// reaches into fapigo's internal packages; see ARCHITECTURE.md's
// "Relationship to FAPIgo" for why that's a hard boundary, not a style
// choice.
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
// Credential Endpoint doesn't implement yet (di_vp, unbound
// credentials — and note it never defers issuance itself); both
// credential_configuration_id- and credential_identifier-based
// requests are supported (§8.2 — see AuthorizedRequest's own
// AuthorizationDetails field for the latter's own authorization
// source); a jwt-type proof's binding key may be conveyed as jwk, or as
// kid/x5c when Dependencies.ProofBindingKeys is configured (see
// ProofBindingKeyResolver's own doc comment). Encrypted Requests and
// Responses (§10) are supported for both the Credential and Deferred
// Credential Endpoints via DecryptRequestBody/EncryptResponseBody —
// see their own doc comments, and Config.RequestEncryption/
// Config.ResponseEncryption for how an issuer opts in (published in
// Metadata's own credential_request_encryption/credential_response_encryption).
// CreateCredentialOffer's own doc comment for what the Credential
// Offer doesn't cover yet (issuing a pre-authorized_code or
// issuer_state remains caller-supplied — this package treats offer
// construction and pre-authorized_code redemption as two separate
// steps; see PreAuthorizedCodeStore's own doc comment for the split),
// DeferredTransactionRecord's own doc comment for why this package
// never creates or resolves a Deferred Issuance transaction itself,
// and NotificationHandler's own doc comment for why reacting to a
// Notification Request's event is entirely the caller's business
// logic. authorization_server.go documents the recipe for pairing
// this package with a real fapigo/server.Server for the Authorization
// Code Flow's own Authorization/Token Endpoints — see its own doc
// comment, and oid4vci.IssuerStateExtension for the shared §4.1.1
// issuer_state parameter registration both sides need.
// ExchangePreAuthorizedCode is the one grant entirely outside
// fapigo/server's own scope (the same way it's outside
// fapigo/client's own scope on the wallet side) — it's this package's
// own server-side Token Endpoint handling, built on
// internal/dpop.Verify (RFC 9449 DPoP proof verification) and
// internal/jwk.JWK.Thumbprint (RFC 7638, for the issued access
// token's own cnf.jkt), with optional RFC 9449 §8 DPoP nonce-challenge
// support via Dependencies.DPoPNonces — see its own doc comment, and
// ExchangePreAuthorizedCode's own for the ordering guarantee that
// makes it safe to combine with a single-use pre-authorized_code.
// ARCHITECTURE.md
// describes what's still missing elsewhere.
package issuer
