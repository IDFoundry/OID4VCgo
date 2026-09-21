package oid4vci

// JOSE signature algorithm identifiers accepted by every jose.Alg-typed
// configuration field across this module — verifier.Config.SigningAlg,
// wallet.Config.ProofSigningAlg, issuer's SDJWTSigner/MdocSigner Alg
// fields, and haip's WalletConfig/VerifierConfig equivalents. jose.Alg
// itself is defined in internal/jose, which (like every internal
// package) an external caller of this module cannot import — so
// without a named constant here, an external config literal has to
// spell the algorithm as a bare, unchecked string ("ES256") with no
// compile-time typo protection. These are untyped string constants,
// each directly assignable to any jose.Alg-typed field without an
// explicit conversion, the same way jose.Alg's own ES256/EdDSA
// constants are used internally. Only the two algorithms internal/jose
// actually supports are defined here; see that package's own doc
// comment before adding a third.
const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4) — HAIP
	// 1.0's own minimum signing algorithm requirement.
	ES256 = "ES256"

	// EdDSA is pure EdDSA over Ed25519 (RFC 8037 §3.1).
	EdDSA = "EdDSA"
)
