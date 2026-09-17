// Package jose implements a small, self-contained JWS compact
// serialization signer/verifier (RFC 7515), used internally by
// credential/sdjwtvc (and, in time, attestation and statuslist) for the
// Issuer-signed JWT and Key Binding JWT that SD-JWT VC needs.
//
// It deliberately supports a small, curated algorithm set — ES256
// (P-256/SHA-256) and EdDSA (Ed25519) — rather than the full JWA
// registry, chosen because they're what SD-JWT VC's own examples use
// and what real wallets/issuers commonly deploy today. Extend as a real
// need arises (a HAIP requirement, an OIDF conformance-suite algorithm)
// rather than pre-building every JWA algorithm speculatively.
//
// This is intentionally not FAPIgo's keys.KeyManager: that package's
// SigningPurpose is a closed enum defined entirely in FAPIgo, so
// OID4VCgo cannot add the purposes it would need (credential signing,
// Key Binding JWT signing, key/wallet attestation signing) without a
// change in FAPIgo itself — see ARCHITECTURE.md. Sign here takes a
// plain crypto.Signer instead, so a caller can adapt anything
// crypto.Signer-shaped — a static key today, or a FAPIgo
// keys.KeyManager-backed adapter once suitable purposes exist there —
// without this package or its callers depending on that enum.
package jose
