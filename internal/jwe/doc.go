// Package jwe implements a small, self-contained JWE Compact
// Serialization encryptor/decryptor (RFC 7516), for OID4VCI 1.0 §10's
// Encrypted Credential Requests and Responses.
//
// It deliberately supports a small, curated combination rather than
// the full JWA registry: ECDH-ES (RFC 7518 §4.6, Direct Key
// Agreement — no key wrapping) over a P-256 EC key, with AES-GCM
// content encryption (RFC 7518 §5.3: A128GCM/A192GCM/A256GCM) and
// optional raw-DEFLATE compression ("zip":"DEF", RFC 7516). This is
// exactly §10's own worked example combination (Appendix I.1's
// "alg":"ECDH-ES", enc_values_supported: ["A128GCM"]) and, like
// internal/jose's own ES256/EdDSA scope, is meant to be extended only
// when a real need arises (ECDH-ES+A*KW key wrapping, RSA-OAEP) rather
// than pre-built speculatively. Decrypt does read a sender's own
// "apu"/"apv" header members into the Concat KDF's own OtherInfo when
// present (RFC 7518 §4.6.1.2/§4.6.1.3) — confirmed live against the
// OpenID Foundation conformance suite's own direct_post.jwt responses,
// which always set both; getting this wrong doesn't corrupt the
// plaintext, it silently derives the wrong key and surfaces only as an
// opaque AEAD failure. Encrypt never sets them itself (both are
// OPTIONAL; omitting them is spec-legal) — add that side only once a
// real peer is found to require it.
//
// crypto/ecdh does the actual ECDH scalar multiplication — this
// package never touches elliptic-curve point arithmetic directly, the
// same restraint internal/jose shows by leaning on crypto/ecdsa rather
// than hand-rolling signature math. Only the Concat KDF (NIST SP
// 800-56A §5.8.1, as profiled by RFC 7518 §4.6.2) and the JWE Compact
// Serialization framing around AES-GCM are implemented here, matching
// the narrow, precisely-specified-primitive style internal/hkdf
// already established for RFC 5869.
package jwe
