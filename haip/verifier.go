package haip

import (
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
)

// VerifierRecommendations is what RecommendedVerifierConfig returns:
// the pieces of a verifier.Config HAIP 1.0 actually grounds a specific
// recommendation for. It is not a complete verifier.Config —
// verifier.Config's own ClientCertificate/ResponseURI fields are
// deployment-specific (an Ecosystem's own Verifier identity and
// endpoint URL, neither of which HAIP numbers), so they're deliberately
// left out rather than padded with an unlabeled guess — the same
// restraint IssuerRecommendations/WalletRecommendations already apply
// to their own packages' ungrounded fields.
type VerifierRecommendations struct {
	// SigningAlg is ready to assign directly to verifier.Config's own
	// field of the same name — see RecommendedJOSEAlgorithm's own
	// citation (HAIP 1.0 §7's minimum, numbering "signed presentation
	// requests" on the Wallet's own validating side; a Verifier signs
	// its Request Object with the same algorithm so that validation
	// succeeds).
	SigningAlg jose.Alg

	// EncValuesSupported is ready to assign directly to verifier.Config's
	// own field of the same name — HAIP 1.0 §5's own explicit
	// requirement: "The JWE enc ... values A128GCM and A256GCM ... MUST
	// be supported by Verifiers." Unlike Wallets (which HAIP only
	// requires to support one or the other, SHOULD-preferring A256GCM),
	// a Verifier has no choice here — both are mandatory — so this is a
	// fixed pair, not a single algorithm like SigningAlg.
	EncValuesSupported []jwe.Enc
}

// RecommendedVerifierConfig returns HAIP 1.0's own recommendations for
// the parts of a verifier.Config it actually grounds a specific value
// for. As with RecommendedIssuerConfig/RecommendedWalletConfig, this is
// a starting point to call and override, not something verifier.New
// applies on its own.
func RecommendedVerifierConfig() VerifierRecommendations {
	return VerifierRecommendations{
		SigningAlg:         RecommendedJOSEAlgorithm,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
	}
}
