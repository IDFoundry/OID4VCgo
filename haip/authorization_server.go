package haip

import (
	"fmt"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/extension"
	"github.com/idfoundry/fapigo/server"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo"
)

// RecommendedClientAttestationAlgorithm is the algorithm a Wallet
// Attestation and its PoP are accepted under: ES256, HAIP 1.0 §7's
// minimum — the fapigo counterpart of RecommendedJOSEAlgorithm.
const RecommendedClientAttestationAlgorithm = fapi.ES256

// RecommendedAuthorizationServerConfig returns the parts of a
// fapigo/server.Config that an Authorization Server for a HAIP 1.0
// Credential Issuer needs, starting from fapigo's own
// RecommendedAlgorithms and RecommendedLimits:
//
//   - Profile ProfileFAPISecurity and OAuthOnly: HAIP 1.0 §4 builds on
//     the FAPI 2.0 Security Profile, and the Credential Issuer's
//     Authorization Server is plain OAuth 2.0, not OpenID Connect.
//   - AttestationBasedClientAuthentication, with the ClientAttestation
//     and ClientAttestationPoP algorithm sets set to
//     RecommendedClientAttestationAlgorithm: HAIP 1.0 §4.4.1 requires
//     Wallet Attestation as the Wallet's client authentication.
//   - Extensions registering oid4vci.IssuerStateExtension: without it,
//     the issuer_state an issuer-initiated flow's Credential Offer
//     carries (OID4VCI 1.0 §4.1.1) is dropped at PAR.
//   - Limits.MaxClientAttestationPoPAge set to MaxDPoPProofAge: a PoP,
//     like a DPoP proof, is created fresh for each request.
//
// The caller sets the rest: Issuer, Endpoints and Assurance, under
// server.AssuranceProduction Deployment (single instance or
// horizontally scaled, which server.New then requires), and
// Limits.MaxClientAttestationLifetime — how long a Wallet Attestation
// stays usable is the Wallet Provider's and the ecosystem's decision,
// which HAIP doesn't number, so it's left zero and server.New refuses
// the Config until it's set. Server dependencies are the caller's too;
// for Wallet Attestations trusted by certificate chain, use
// server.X5CAttesterChain with server.AttesterIssuerBoundToAnchor and
// each Wallet Provider's anchor in Anchors, bound to the providers it
// may vouch for, so one Wallet Provider can't attest for another's
// wallets even under a shared trust list. Under production assurance,
// server.New takes only an anchor source declaring itself hardened for
// live fetches, as server.StaticAttesterAnchors does.
func RecommendedAuthorizationServerConfig() (server.Config, error) {
	extensions, err := extension.NewRegistry(oid4vci.IssuerStateExtension)
	if err != nil {
		return server.Config{}, fmt.Errorf("haip: authorization server extensions: %w", err)
	}
	algorithms := server.RecommendedAlgorithms()
	algorithms.ClientAttestation = server.AlgorithmSet{RecommendedClientAttestationAlgorithm}
	algorithms.ClientAttestationPoP = server.AlgorithmSet{RecommendedClientAttestationAlgorithm}
	limits := server.RecommendedLimits()
	limits.MaxClientAttestationPoPAge = limits.MaxDPoPProofAge
	return server.Config{
		Profile:                              server.ProfileFAPISecurity,
		OAuthOnly:                            true,
		AttestationBasedClientAuthentication: true,
		Algorithms:                           algorithms,
		Limits:                               limits,
		Extensions:                           extensions,
	}, nil
}

// RecommendedWalletClient returns the registration of a Wallet that
// authenticates with a Wallet Attestation (HAIP 1.0 §4.4.1) issued by
// attesterIssuer — its Wallet Provider, the attestation's "iss" —
// under RecommendedClientAttestationAlgorithm. Add RedirectURIs and
// AllowedScopes, then pass it to storage.NewRegisteredClient.
func RecommendedWalletClient(id fapi.ClientID, attesterIssuer string) storage.RegisteredClientConfig {
	return storage.RegisteredClientConfig{
		ID:                         id,
		ClientAuthMethod:           storage.ClientAuthMethodAttestation,
		ExpectedAttesterIssuer:     attesterIssuer,
		ClientAttestationAlgorithm: RecommendedClientAttestationAlgorithm,
	}
}
