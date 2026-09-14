// Package cose implements a small, self-contained COSE_Sign1 (RFC 9052
// §4.2) signer/verifier, used internally by credential/mdoc for
// IssuerAuth (ISO/IEC 18013-5's COSE_Sign1-wrapped Mobile Security
// Object) and, in time, statuslist's CWT-encoded status list tokens.
//
// It supports the same curated algorithm set as internal/jose — ES256
// (P-256/SHA-256, COSE algorithm -7) and EdDSA (Ed25519, COSE algorithm
// -8), RFC 9053 §2 — for the same reason: these are what mdoc's own
// worked examples use and what real wallets/issuers commonly deploy
// today. Extend as a real need arises rather than pre-building the full
// COSE algorithm registry.
//
// This package only builds and verifies the COSE_Sign1 envelope itself
// — the four-element [protected, unprotected, payload, signature] array
// RFC 9052 §4.2 defines, untagged (mdoc's own CDDL, "IssuerAuth =
// COSE_Sign1", uses the untagged form, not COSE_Sign1_Tagged). It knows
// nothing about IssuerSigned, the Mobile Security Object, or any other
// mdoc-specific CBOR structure — those are credential/mdoc's job to
// define with their own CBOR struct tags on top of
// github.com/fxamacker/cbor/v2, the same layering credential/sdjwtvc
// uses on top of internal/jose (jose knows JWS, sdjwtvc knows SD-JWT
// VC's claims).
//
// Sign always embeds the payload; COSE's detached-payload form ("payload
// : nil" with the actual bytes carried out of band) isn't supported
// since mdoc's IssuerAuth never uses it.
package cose
