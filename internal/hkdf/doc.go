// Package hkdf implements HKDF (RFC 5869) using SHA-256, the key
// derivation function ISO/IEC 18013-5 §12.4.5 uses to derive mdoc's
// ephemeral MAC key (EMacKey) from an ECDH shared secret — the one
// piece of key-agreement machinery credential/mdoc's DeviceMac needs
// that internal/cose deliberately doesn't own (see that package's doc
// comment).
//
// Only SHA-256 is implemented, since that's the only hash §12.4.5
// requires. Hand-rolled rather than a dependency (golang.org/x/crypto/hkdf)
// because RFC 5869's Extract/Expand steps are two short, exactly
// specified HMAC-based operations with the RFC's own published test
// vectors to validate against — unlike CBOR (see internal/cose's doc
// comment on why that was too large a surface to hand-roll safely).
package hkdf
