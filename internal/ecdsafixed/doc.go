// Package ecdsafixed converts between the ASN.1 DER ECDSA signature
// encoding Go's crypto.Signer produces (SEC1 / RFC 3279 §2.2.3) and the
// fixed-width big-endian R||S encoding both JWS (RFC 7518 §3.4) and COSE
// (RFC 9053 §2.1) require instead — the one piece of signature-envelope
// logic internal/jose and internal/cose need identically, since both
// specs made the same encoding choice for ECDSA.
package ecdsafixed
