// Package jwk implements a small, self-contained JWK (RFC 7517)
// marshaler/parser for the two key types internal/jose signs with:
// P-256 EC keys and Ed25519 OKP keys. It is deliberately not a
// general-purpose JWK codec — extend alongside internal/jose if a real
// need for another key type arises.
//
// This exists as its own package (rather than living in attestation,
// which needed it first) because issuer's Credential Endpoint also
// needs to parse a Wallet-supplied JWK — the "jwk" header of a jwt-type
// key proof (OID4VCI 1.0 Appendix F.1) — into a crypto.PublicKey, the
// mirror image of attestation's own need to marshal a public key into
// JWK form to compare against a Key Attestation's attested_keys.
package jwk
