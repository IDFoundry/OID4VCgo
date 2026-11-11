// Package jose implements a small, self-contained JWS compact
// serialization signer/verifier (RFC 7515), used internally by
// credential/sdjwtvc (and, in time, attestation and statuslist) for the
// Issuer-signed JWT and Key Binding JWT that SD-JWT VC needs.
//
// It deliberately supports a small, curated algorithm set rather than
// the full JWA registry. Sign produces ES256 (P-256/SHA-256) and EdDSA
// (Ed25519) only — HAIP 1.0 §7's minimum, and what SD-JWT VC's own
// examples use. Verify also accepts ES384 (P-384/SHA-384) and ES512
// (P-521/SHA-512), which HAIP's minimum doesn't exclude and deployed
// peers use (the EUDI reference verifier signs its Request Objects
// ES512 by default), each with keys on its own curve only. Extend as a
// real need arises (a HAIP requirement, an OIDF conformance-suite
// algorithm, an interop peer) rather than pre-building every JWA
// algorithm speculatively.
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
