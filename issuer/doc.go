// Package issuer implements the OID4VCI 1.0 Credential Issuer role
// (the server side): the Nonce Endpoint (§7), Credential Issuer
// Metadata (§12.2), and — as they land — the Credential Offer,
// Credential, Deferred Credential and Notification Endpoints.
//
// This package builds on FAPIgo's public server package for
// everything OID4VCI relies on FAPI 2.0/OAuth 2.0 for — PAR, DPoP,
// client authentication (including Wallet Attestation, via
// storage.ClientAuthMethodAttestation), token issuance — rather than
// reimplementing any of it. It never reaches into fapigo's internal
// packages; see ARCHITECTURE.md's "Relationship to FAPIgo" for why
// that's a hard boundary, not a style choice.
//
// # Status
//
// Only the Nonce Endpoint and a Metadata shape covering what SD-JWT VC
// issuance needs exist so far — no encryption, batch issuance, or
// display metadata yet, and no live Credential Endpoint. See
// ARCHITECTURE.md for the planned shape of what's still missing.
package issuer
