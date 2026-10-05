package haip

import oid4vci "github.com/idfoundry/oid4vcgo"

// RecommendedJOSEAlgorithm and RecommendedCOSEAlgorithm are the
// digital signature algorithm HAIP 1.0 §7 requires every Issuer,
// Verifier and Wallet to support "at a minimum," for validating Wallet
// Attestations, Key Attestations, and the jwt proof type (Issuers),
// among other purposes listed there: "ECDSA with P-256 and SHA-256
// (JOSE algorithm identifier ES256; COSE algorithm identifier -7 or -9,
// as applicable)".
//
// §7 also names COSE identifier -9 "as applicable"; this repo's
// COSE implementation only supports -7 (RFC 9053's own ES256), which is
// what credential/mdoc's IssuerAuth and DeviceSignature actually sign
// with, so RecommendedCOSEAlgorithm names that one.
//
// §7 states this as a minimum, not an exhaustive allow-list —
// "Ecosystem-specific profiles of this specification MAY mandate
// additional cryptographic suites" — so these are a starting point for
// oid4vci.ProofTypeConfiguration.ProofSigningAlgValuesSupported (or a
// CredentialConfiguration's own signing-algorithm fields), not a
// ceiling.
const (
	RecommendedJOSEAlgorithm oid4vci.JOSEAlg = oid4vci.ES256
	RecommendedCOSEAlgorithm                 = oid4vci.COSEES256
)
