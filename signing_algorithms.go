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
// statuslist.IssueTokenCWTX5Chain, issuer.MdocSigner.Alg — the COSE
// counterparts of ES256 and EdDSA below.
const (
	// COSEES256 is ECDSA using P-256 and SHA-256 (COSE algorithm -7).
	COSEES256 COSEAlg = cose.ES256

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
// without an explicit conversion. Only the two algorithms internal/jose
// actually supports are defined here; see that package's own doc
// comment before adding a third.
const (
	// ES256 is ECDSA using P-256 and SHA-256 (RFC 7518 §3.4) — HAIP
	// 1.0's own minimum signing algorithm requirement.
	ES256 = "ES256"

	// EdDSA is pure EdDSA over Ed25519 (RFC 8037 §3.1).
	EdDSA = "EdDSA"
)
