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
// when a real need arises (ECDH-ES+A*KW key wrapping, RSA-OAEP, apu/apv
// party info) rather than pre-built speculatively — this package
// currently has no apu/apv support at all, treating both as absent in
// the RFC 7518 §4.6.2 Concat KDF's own OtherInfo.
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
