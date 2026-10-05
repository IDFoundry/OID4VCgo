package oid4vci

import "github.com/idfoundry/oid4vcgo/internal/jwe"

// JWEAlg, JWEEnc and JWEZip name internal/jwe's key-management,
// content-encryption and compression types, which an external caller
// of this module can't import — like signing_algorithms.go's
// constants, so a configuration that takes a list of them
// (issuer.RequestEncryptionSupport, issuer.ResponseEncryptionSupport,
// verifier.Config.EncValuesSupported) can be written outside this
// module: []oid4vci.JWEEnc{oid4vci.A256GCM}.
type (
	JWEAlg = jwe.Alg
	JWEEnc = jwe.Enc
	JWEZip = jwe.Zip
)

// ECDHES is ECDH-ES Direct Key Agreement (RFC 7518 §4.6), the one JWE
// "alg" internal/jwe supports.
const ECDHES JWEAlg = jwe.ECDHES

// JWE "enc" and "zip" values internal/jwe supports.
const (
	// A128GCM and A256GCM are AES-GCM with 128- and 256-bit keys (RFC
	// 7518 §5.3) — the values HAIP 1.0 §5.1 requires for OpenID4VP
	// response encryption.
	A128GCM JWEEnc = jwe.A128GCM
	A256GCM JWEEnc = jwe.A256GCM

	// ZipDEF is DEFLATE compression before encryption (RFC 7516 §4.1.3).
	ZipDEF JWEZip = jwe.DEF
)
