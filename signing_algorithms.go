package oid4vci

import (
	"github.com/idfoundry/oid4vcgo/internal/cose"
	"github.com/idfoundry/oid4vcgo/internal/jose"
)

// JOSEAlg and COSEAlg name internal/jose's and internal/cose's signature
// algorithm types, which an external caller of this module can't
// import. Public interfaces return them — verifier.SDJWTVCIssuerKeyResolver,
// verifier.MdocIssuerKeyResolver, issuer.AttestationVerifier,
// issuer.ProofBindingKeyResolver — so an implementation outside this
// module declares its method with these names:
//
//	func (r MyResolver) ResolveIssuerKey(ctx context.Context, header, payload map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error)
type (
	JOSEAlg = jose.Alg
	COSEAlg = cose.Alg
)

// COSE signature algorithm identifiers (RFC 9053) accepted by every
// cose.Alg-typed parameter and field — mdoc.Issue, mdoc.Verify,
// statuslist.IssueTokenCWTX5Chain, issuer.MdocSigner.Alg. COSEES256
// and COSEEdDSA are the COSE counterparts of ES256 and EdDSA below;
// COSEES384 and COSEES512 are those of ES384 and ES512, but unlike
// them sign as well as verify: mdoc and CWT tokens sign with them.
const (
	// COSEES256 is ECDSA using P-256 and SHA-256 (COSE algorithm -7).
	COSEES256 COSEAlg = cose.ES256

	// COSEES384 is ECDSA using P-384 and SHA-384 (COSE algorithm -35).
	COSEES384 COSEAlg = cose.ES384

	// COSEES512 is ECDSA using P-521 and SHA-512 (COSE algorithm -36).
	COSEES512 COSEAlg = cose.ES512

	// COSEEdDSA is EdDSA (COSE algorithm -8).
	COSEEdDSA COSEAlg = cose.EdDSA
)

// JOSE signature algorithm identifiers accepted by every jose.Alg-typed
// configuration field across this module — verifier.Config.SigningAlg,
// wallet.Config.ProofSigningAlg, issuer's SDJWTSigner/MdocSigner Alg
// fields, and haip's WalletConfig/VerifierConfig equivalents. jose.Alg
// itself is defined in internal/jose, which (like every internal
// package) an external caller of this module cannot import — so
// without a named constant here, an external config literal has to
// spell the algorithm as a bare, unchecked string ("ES256") with no
// compile-time typo protection. These are untyped string constants,
// each directly assignable to any JOSEAlg-typed field or parameter
// without an explicit conversion. ES256 and EdDSA are the algorithms
// this module signs with; ES384 and ES512 it only verifies (HAIP 1.0
// §7 makes ES256 a minimum, not a ceiling), so they're for lists of
// what a party accepts — proof_signing_alg_values_supported, or
// verifier.SDJWTVCFormatSupport's sd-jwt_alg_values — and a signing
// field refuses them. See internal/jose's own doc comment before adding
// another.
const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4) — HAIP
	// 1.0's own minimum signing algorithm requirement.
	ES256 = "ES256"

	// ES384 is ECDSA using P-384 and SHA-384 (RFC 7518 §3.4). Verified,
	// never signed with.
	ES384 = "ES384"

	// ES512 is ECDSA using P-521 and SHA-512 (RFC 7518 §3.4). Verified,
	// never signed with.
	ES512 = "ES512"

	// EdDSA is pure EdDSA over Ed25519 (RFC 8037 §3.1).
	EdDSA = "EdDSA"
)
