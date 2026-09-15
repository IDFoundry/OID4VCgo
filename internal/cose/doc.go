// Package cose implements small, self-contained COSE_Sign1 (RFC 9052
// §4.2) and COSE_Mac0 (RFC 9052 §6.2) signers/verifiers, used
// internally by credential/mdoc (IssuerAuth, DeviceSignature,
// DeviceMac — ISO/IEC 18013-5) and statuslist (CWT-encoded Status List
// Tokens).
//
// It supports the same curated algorithm set as internal/jose for
// signing — ES256 (P-256/SHA-256, COSE algorithm -7) and EdDSA
// (Ed25519, COSE algorithm -8), RFC 9053 §2 — for the same reason:
// these are what mdoc's own worked examples use and what real
// wallets/issuers commonly deploy today. HMAC256 ("HMAC 256/256", COSE
// algorithm 5, mac0.go) is the only MAC algorithm supported, since it's
// the only one mdoc's DeviceMac uses. Extend as a real need arises
// rather than pre-building the full COSE algorithm registry.
//
// This package only builds and verifies the COSE_Sign1/COSE_Mac0
// envelopes themselves — the four-element [protected, unprotected,
// payload, signature/tag] arrays RFC 9052 §4.2/§6.2 define.
// Sign/Verify/DecodeUnverified handle the untagged COSE_Sign1 form
// (mdoc's own CDDL, "IssuerAuth = COSE_Sign1", uses this form, not
// COSE_Sign1_Tagged); SignTagged/VerifyTagged/DecodeUnverifiedTagged
// handle #6.18(COSE_Sign1) instead, for a context that doesn't
// otherwise establish the bytes are a COSE_Sign1
// (draft-ietf-oauth-status-list-12 §5.2's CWT-format Status List Token
// uses the tagged form). SignDetached/VerifyDetached handle a detached
// COSE_Sign1 payload (mdoc's DeviceSignature, §12.4.6); ComputeMAC/
// VerifyMAC are COSE_Mac0's only form here, since mdoc's DeviceMac
// (§12.4.5) always uses a detached payload. It knows nothing about
// IssuerSigned, the Mobile Security Object, DeviceAuthentication,
// StatusList, or any other caller-specific CBOR structure, nor about
// key agreement (ComputeMAC/VerifyMAC take an already-derived HMAC key
// — deriving mdoc's EMacKey via ECKA-DH/HKDF is credential/mdoc's job)
// — those are credential/mdoc's and statuslist's job to define with
// their own CBOR struct tags on top of github.com/fxamacker/cbor/v2,
// the same layering credential/sdjwtvc uses on top of internal/jose
// (jose knows JWS, sdjwtvc knows SD-JWT VC's claims).
package cose
