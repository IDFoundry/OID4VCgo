// Package verifier implements the OID4VP 1.0 Verifier (Relying Party)
// role, profiled by HAIP 1.0 §5 — the presentation half of HAIP, as
// issuer/wallet implement OID4VCI's own issuance half.
//
// Unlike issuance, the presentation flow builds on none of FAPI 2.0's
// AS/RP OAuth machinery: no PAR, no Token Endpoint, no client
// authentication handshake in the OAuth-grant sense. An OID4VP
// Authorization Request is a JAR-signed Request Object [RFC9101]
// carrying a dcql_query (package dcql), answered with a VP Token via a
// response mode HAIP fixes to direct_post.jwt for the redirect flow
// this package implements — self-contained on top of JOSE primitives
// this repo already owns (internal/jose, internal/jwe,
// internal/jwk.Thumbprint) and the two existing credential format
// packages (credential/sdjwtvc, credential/mdoc) for the actual
// Presentation verification. This package has no FAPIgo dependency at
// all, unlike issuer/wallet's OID4VCI roles.
//
// # Status
//
// BuildAuthorizationRequest constructs a signed redirect-flow
// Authorization Request (x509_hash Client Identifier Prefix,
// direct_post.jwt response mode, per §5 and HAIP §5's own profile of
// it). ParseDirectPostJWTResponse decrypts and parses the resulting
// response (§8.1/§8.3.1). VerifyResponse implements §8.6's own VP
// Token Validation for the "dc+sd-jwt" format only — see its own doc
// comment for exactly what Phase 2 does and doesn't cover (no
// "multiple", no claim_sets, no CredentialSets orchestration, no
// "mso_mdoc"). Not yet implemented: OpenID4VPHandover/DeviceResponse
// CBOR construction and verification for the "mso_mdoc" format, and
// the DC API flow entirely (request_uri hosting/dereferencing is also
// out of scope for this package — like issuer.CreateCredentialOffer's
// own by-reference split, hosting the built Request Object at a
// request_uri is the caller's own job). See ARCHITECTURE.md for the
// full roadmap.
package verifier
