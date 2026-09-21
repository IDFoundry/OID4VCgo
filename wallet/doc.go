// Package wallet implements the OID4VCI 1.0 Wallet role (the client
// side): resolving a Credential Offer (§4), generating jwt-type and
// attestation-type key proofs (Appendix F.1/F.3), and driving the
// Credential Endpoint (§8), Nonce Endpoint (§7), Deferred Credential
// Endpoint (§9) and Notification Endpoint (§11). It is built on fapigo/client
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
// ClientAuthentication/DPoP, matching HAIP §7's own minimum. HAIP
// §4.4.1's Wallet Attestation client authentication —
// storage.ClientAuthMethodAttestation, added so fapigo/server can
// verify one (see ARCHITECTURE.md's "Relationship to FAPIgo") — is now
// fully supported client-side too: set Config.ClientAuthMethod to it,
// Config.Algorithms.ClientAttestationPoP, and supply a
// Dependencies.Attestation (an AttestationSource holding the wallet's
// own, out-of-band-issued Client Attestation JWT). fapigo/client builds
// and signs the per-request PoP JWT itself. See
// cmd/conformance-issuer's own TestFullFlow_RealClientDrivesAttestationAuth
// for a genuine end-to-end proof — a real fapigo/client wallet
// authenticating this way against a real fapigo/server-based
// Authorization Server and issuer-based Credential Issuer.
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
// GenerateAttestationProof builds the other key proof this package
// supports: a Key Attestation JWT (Appendix D.1) for the attestation
// proof type (Appendix F.3), by delegating to the attestation
// package's own Issue — the same package issuer's Credential Endpoint
// already verifies an attestation proof against. Unlike a jwt-type
// proof, RequestCredential doesn't build this one itself: the c_nonce
// must already be baked into the signed attestation before the
// Credential Request is sent, so a caller drives RequestNonce, then
// GenerateAttestationProof, then RequestCredential (passing the result
// as CredentialRequest.Attestation), in that order. Building a Key
// Attestation is, in most real deployments, a secure element's or an
// OS attestation service's job rather than pure application logic;
// GenerateAttestationProof exists for the cases where the caller's own
// signer can produce one directly.
//
// GenerateProofWithKeyID and GenerateProofWithX5C sign a jwt-type
// proof (Appendix F.1) the same way GenerateProof does, but binding it
// via a "kid" or "x5c" header instead of embedding the key material as
// "jwk" — for a Credential Issuer that trusts a key by identifier or
// certificate rather than needing it conveyed inline. This package
// takes no position on how kid/x5c actually resolve to a trusted key
// on the issuer's own side; see issuer.ProofBindingKeyResolver's doc
// comment for that half. Since RequestCredential's own Keys field only
// ever builds jwk-conveyed proofs, a caller wanting kid/x5c passes the
// result of either method through CredentialRequest.JWTProofs instead.
//
// GenerateProofWithKeyAttestation signs a jwt-type proof the same way
// GenerateProof does, jwk-conveyed, but also embeds a Key Attestation
// JWT as the proof's own "key_attestation" header member — Appendix
// D.1's nested-attestation case for the jwt proof type, distinct from
// GenerateAttestationProof's standalone attestation proof type above.
// Like GenerateProofWithKeyID/GenerateProofWithX5C, the result goes
// through CredentialRequest.JWTProofs, not Keys.
//
// RequestCredential/RequestDeferredCredential also implement §10's
// Encrypted Requests/Responses, symmetric with issuer's own
// DecryptRequestBody/EncryptResponseBody: setting
// CredentialRequest.RequestEncryption (or DeferredCredentialRequest's
// own field) encrypts the outbound request body to the Issuer's own
// published credential_request_encryption key (this package doesn't
// fetch or parse Issuer metadata itself — the caller supplies one JWK
// from it via RequestEncryption.RecipientJWK); setting
// .ResponseEncryption additionally requests an encrypted Response —
// RequestCredential generates a fresh ephemeral P-256 key pair per
// call and decrypts the Response transparently, so the CredentialResult
// a caller receives is always plaintext regardless. Setting
// ResponseEncryption without RequestEncryption is rejected (§8.2-18:
// "Credential Request encryption MUST be used if the
// credential_response_encryption parameter is included, to prevent it
// being substituted by an attacker"), and so is a Response that
// doesn't honor a requested encryption or that arrives encrypted when
// none was requested — §8.3's own "this is done regardless of the
// content" means the Issuer must always follow through on what was
// asked for either way.
//
// # Status
//
// ResolveCredentialOffer, RequestNonce, GenerateProof,
// GenerateProofWithKeyID, GenerateProofWithX5C, GenerateAttestationProof,
// GenerateProofWithKeyAttestation, RequestCredential, BuildAuthorizationRequest,
// RequestDeferredCredential, RequestNotification, RequestPreAuthorizedCodeToken,
// GenerateDPoPProof
// and DPoPAccessTokenHash exist so far. This package does not yet cover:
//
//   - di_vp proofs (needs W3C VCDM, which this repo doesn't implement,
//     matching issuer's own scope).
//
// A Wallet MUST treat a Credential Offer's contents as untrustworthy
// (§13.5: unauthenticated, integrity-unprotected) — ResolveCredentialOffer
// only checks structural well-formedness (oid4vci.CredentialOffer.Validate),
// never who sent it.
//
// # OID4VP (presentation)
//
// This package also implements the Wallet side of OID4VP: HeldCredential,
// MatchDCQLQuery and PresentCredentials (presentation.go) build a VP
// Token from a DCQL query and this Wallet's own held credentials;
// ParseAuthorizationRequest and BuildDirectPostResponse
// (authorization_request.go, direct_post_response.go) verify an
// incoming redirect-flow Authorization Request and build its encrypted
// direct_post.jwt response — the exact mirror image of verifier's own
// BuildAuthorizationRequest/ParseDirectPostJWTResponse. Both functions
// are pure (no HTTP): POSTing the response is always the caller's own
// job, the same split verifier draws on its side. Fetching request_uri
// is the one HTTP step this package does offer a default for —
// (*Wallet).FetchAuthorizationRequest performs §5.10's plain GET using
// this Wallet's own hardened fapihttp.Client and hands the result
// straight to ParseAuthorizationRequest; a caller wanting §5.10's
// OPTIONAL POST+wallet_nonce variant instead calls
// ParseAuthorizationRequest directly against its own fetch (see
// FetchAuthorizationRequest's own doc comment for why that variant
// isn't built in). Only the "x509_hash" Client Identifier Prefix is
// supported (HAIP's own mandate, and the only one verifier itself
// produces) — no DC API flow, no other client_id scheme, no di_vp
// presentations.
package wallet
