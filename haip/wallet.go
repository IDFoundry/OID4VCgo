package haip

import "github.com/idfoundry/oid4vcigo/internal/jose"

// WalletRecommendations is what RecommendedWalletConfig returns: the
// pieces of a wallet.Config HAIP 1.0 actually grounds a specific
// recommendation for. It is not a complete wallet.Config — wallet.Config's
// own Fetch field (SSRF/redirect/timeout policy for the Nonce Endpoint
// and a by-reference Credential Offer fetch) is deployment-specific,
// not something HAIP numbers, so it's deliberately left out rather
// than padded with an unlabeled guess — the same restraint
// IssuerRecommendations already applies to issuer.Config's own
// ungrounded fields.
type WalletRecommendations struct {
	// ProofSigningAlg is ready to assign directly to wallet.Config's
	// own field of the same name — see RecommendedJOSEAlgorithm's own
	// citation (HAIP 1.0 §7's minimum, numbering "jwt proof type as
	// specified in Appendix E of [OIDF.OID4VCI]" on the Issuer's own
	// validating side; a Wallet signs with the same algorithm so that
	// validation succeeds). wallet.Config reuses this one value for
	// both the jwt-type key proof (Appendix F.1, via GenerateProof/
	// GenerateProofWithKeyID/GenerateProofWithX5C) and the
	// pre-authorized_code Flow's own RFC 9449 DPoP proof
	// (GenerateDPoPProof) — HAIP 1.0 §4 makes DPoP itself mandatory but
	// doesn't separately number an algorithm for it, so this
	// recommendation carries over by construction (one Config field,
	// not a second citation).
	ProofSigningAlg jose.Alg
}

// RecommendedWalletConfig returns HAIP 1.0's own recommendation for the
// one part of a wallet.Config it actually grounds a specific value
// for. As with RecommendedIssuerConfig, this is a starting point to
// call and override, not something wallet.New applies on its own.
func RecommendedWalletConfig() WalletRecommendations {
	return WalletRecommendations{ProofSigningAlg: RecommendedJOSEAlgorithm}
}
