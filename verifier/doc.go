// Package verifier implements the OID4VP 1.0 Verifier (Relying Party)
// role, profiled by HAIP 1.0 §5 — the presentation half of HAIP, as
// issuer/wallet implement OID4VCI's own issuance half.
//
// Unlike issuance, the presentation flow builds on none of FAPI 2.0's
// AS/RP OAuth machinery: no PAR, no Token Endpoint, no client
// authentication handshake in the OAuth-grant sense. An OID4VP
// Authorization Request is a JAR-signed Request Object [RFC9101]
// carrying a dcql_query (package dcql), answered with a VP Token —
// via direct_post.jwt for the redirect flow, or dc_api.jwt for the DC
// API flow (Appendix A/HAIP §5.2) — self-contained on top of JOSE
// primitives this repo already owns (internal/jose, internal/jwe,
// internal/jwk.Thumbprint) and the two existing credential format
// packages (credential/sdjwtvc, credential/mdoc) for the actual
// Presentation verification. This package has no FAPIgo dependency at
// all, unlike issuer/wallet's OID4VCI roles.
//
// # Where to start
//
// For the redirect flows, use Transactions: Begin a request, mount its
// RequestObjectHandler and ResponseHandler, and read the result with
// Lookup (cross-device) or Redeem (same-device). For the Digital
// Credentials API, BeginDCAPI a request, hand its Request to the page
// for navigator.credentials.get, and pass the answer the page posts
// back to HandleDCAPIResponse. It keeps each request's
// secrets, routes each answer to its request, verifies it, and binds
// the result to the browser that asked — the state handling OpenID4VP
// §8.2 and §13.3 require, which the lower-level functions below leave
// to the caller.
//
// # Status
//
// BuildAuthorizationRequest constructs a signed redirect-flow
// Authorization Request (x509_hash Client Identifier Prefix,
// direct_post.jwt response mode, per §5 and HAIP §5's own profile of
// it). BuildDCAPIAuthorizationRequest constructs a signed DC API
// request instead (Appendix A.3.2.1, JWS Compact Serialization;
// unsigned requests and multi-signed JWS JSON Serialization requests
// aren't offered — see its own doc comment). ParseDirectPostJWTResponse
// decrypts and parses the resulting response (§8.1/§8.3.1) — reusable
// as-is for a dc_api.jwt response too, since both share the exact same
// encrypted-JWT-carrying-a-vp_token shape; only the transport differs
// (an HTTP POST body vs. the DC API's own resolved data object), which
// is a caller concern this package's own byte-in/byte-out functions
// never touch. VerifyResponse implements §8.6's own VP Token Validation
// for both the "dc+sd-jwt" and "mso_mdoc" formats, including all of
// §6's own Credential/Claims selection rules: "multiple" (§6.1),
// "claim_sets" (§6.4.1), and "credential_sets" (§6.4.2) — and for both
// the redirect and DC API flows (VerifyResponseRequest.Origin selects
// which, with ExpectedOrigins, the request's, which Origin must be one
// of: the page's own origin, from the Verifier's configuration, never
// from the response's HTTP request): it checks a Presentation's own Holder Binding proof against
// either this Verifier's own Client Identifier or the DC API's own
// Origin-bound audience ("origin:..." per Appendix A.4), and rebuilds
// the mdoc SessionTranscript via oid4vpmdoc.BuildSessionTranscriptBytes
// or BuildDCAPISessionTranscriptBytes to match. ResponseKeyID reads a
// direct_post.jwt response's key ID, to find its request before
// decrypting it. VerifyResponse doesn't check revocation: each
// VerifiedCredential carries its status reference (Claims["status"], or
// MdocStatus) for the caller to resolve with package statuslist.
// RequireValidStatus does, as an Accept; it passes a credential with no
// status reference, which RequireStatusReference refuses.
//
// Certificate revocation is checked for a credential's issuer:
// X5CIssuerKeyResolver and X5ChainIssuerKeyResolver require a
// certrevocation.Checker (their Revocation field), and accept an
// issuer's or document signer's certificate only through a verified
// path on which no certificate is revoked — certrevocation.CRLs with
// the issuer CAs' current CRLs, or certrevocation.NoCheck{} to decline
// explicitly. VerifyResponse and NewTransactions refuse either resolver
// without one. Other certificates aren't checked yet: a status list
// signer's, or a Wallet or Key Attestation signer's, is trusted from
// its chain to the configured roots and its validity period alone. A
// credential's own revocation is its status list's.
//
// The issuer key resolvers establish who a credential's issuer is, not
// which types it may issue: where trusted issuers aren't all authorized
// for every requested type, VerifyResponseRequest.IssuerAuthorized
// decides that per presentation (SD-JWT VC draft-19 §7.7).
// An mdoc requested over the DC API with the "org-iso-mdoc" protocol,
// as Safari does, isn't OpenID4VP: package mdocdcapi builds and verifies
// that.
// request_uri hosting/dereferencing (and, for the DC API flow, actually
// invoking the Digital Credentials API itself) are out of scope for
// this package regardless — like issuer.CreateCredentialOffer's own
// by-reference split, hosting the built Request Object at a
// request_uri, or handing it to the DC API, is the caller's own job.
// See ARCHITECTURE.md for the full roadmap.
package verifier
