package issuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// X5CProofBindingKeyResolver implements ProofBindingKeyResolver by
// validating a jwt-type key proof's own "x5c" header (RFC 7515
// §4.1.6) against Roots — a reference implementation of the one
// concrete trust strategy this package's own doc comments describe
// ("an x5c chain's own trust anchor for x5c"), the issuer-side analog
// of verifier.X5CIssuerKeyResolver. A self-signed leaf is always
// rejected, even if that exact certificate is itself a configured
// root — see internal/certchain.VerifyLeaf's own doc comment for why.
//
// This type only ever resolves "x5c"; it returns an error for a proof
// conveying "kid" instead — kid resolution has no universal shape the
// way an x5c chain does (a DID URL, a private key registry lookup, ...
// are all equally valid and none of them is "the" reference
// implementation), so a caller needing kid-based binding needs their
// own ProofBindingKeyResolver, or one that wraps this type and falls
// back to their own kid lookup when x5c is absent.
type X5CProofBindingKeyResolver struct {
	// Roots is the trust anchor set a presented x5c chain must
	// validate against. REQUIRED.
	Roots *x509.CertPool
	// LeafPolicy, if set, is run on the chain-verified leaf and its
	// verified paths, and can refuse it. Chain validation accepts a
	// leaf with any key usage, so a certificate issued for another role
	// under the same Roots (a relying party's, a wallet provider's)
	// would otherwise be accepted too: prefer Roots that anchor only
	// this role's certificates, and use LeafPolicy to require what
	// distinguishes them (an extended key usage, a certificate policy)
	// where the anchors are shared. nil means
	// DefaultAttestationLeafPolicy, as for X5CAttestationVerifier: a
	// set LeafPolicy replaces it, and AnyAttestationLeaf opts out.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Revocation, if set, checks the proof's certificate chain for
	// revocation: only a verified path LeafPolicy approves and
	// Revocation passes is accepted, and a proof under a revoked
	// certificate is refused with an error wrapping
	// certrevocation.ErrRevoked, and one whose revocation couldn't be
	// decided (certrevocation.ErrNoCurrentCRL, say) is answered with a
	// server error rather than invalid_proof, as for
	// X5CAttestationVerifier.Revocation. nil checks no revocation,
	// which AssuranceProduction refuses: there, pass certrevocation.CRLs,
	// your own Checker, or certrevocation.NoCheck{} to decline. See
	// certrevocation.
	Revocation certrevocation.Checker
}

// ResolveProofBindingKey implements ProofBindingKeyResolver.
func (r X5CProofBindingKeyResolver) ResolveProofBindingKey(ctx context.Context, header map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, "", fmt.Errorf("issuer: proof header has no x5c")
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, "", fmt.Errorf("issuer: proof x5c header is not an array")
	}
	leaf, _, err := resolveX5CLeaf(ctx, entries, r.Roots, attestationLeafPolicy(r.LeafPolicy), r.Revocation)
	if err != nil {
		return nil, "", err
	}
	alg, err := algForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// validateProofBindingKeys refuses an X5CProofBindingKeyResolver, by
// value or by pointer, whose Revocation reports itself incomplete, so
// New refuses it rather than every proof afterwards.
func validateProofBindingKeys(r ProofBindingKeyResolver) error {
	x5c, _ := asX5CProofBindingKeyResolver(r)
	if err := certchain.ValidateRevocation(x5c.Revocation); err != nil {
		return fmt.Errorf("proof_binding_keys: Revocation: %w", err)
	}
	return nil
}

// asX5CProofBindingKeyResolver is r as an X5CProofBindingKeyResolver,
// by value or by non-nil pointer, if it is one.
func asX5CProofBindingKeyResolver(r ProofBindingKeyResolver) (X5CProofBindingKeyResolver, bool) {
	switch t := r.(type) {
	case X5CProofBindingKeyResolver:
		return t, true
	case *X5CProofBindingKeyResolver:
		if t != nil {
			return *t, true
		}
	}
	return X5CProofBindingKeyResolver{}, false
}

// checkProductionX5CRevocation refuses, under AssuranceProduction, an
// X5CAttestationVerifier or X5CProofBindingKeyResolver whose Revocation
// is nil: a certificate whose key was stolen would be accepted until it
// expires. Declining is certrevocation.NoCheck{}, a visible choice, as
// verifier's X5C resolvers and fapigo/server's X5CAttesterChain
// require.
func checkProductionX5CRevocation(deps Dependencies) error {
	const choices = "pass certrevocation.CRLs{...} (a certrevocation.Refresher's Checker), your own certrevocation.Checker, or certrevocation.NoCheck{} to decline"
	if v, ok := asX5CAttestationVerifier(deps.AttestationVerifier); ok && v.Revocation == nil {
		return fmt.Errorf("dependencies.attestation_verifier: X5CAttestationVerifier.Revocation is required under AssuranceProduction: %s", choices)
	}
	if r, ok := asX5CProofBindingKeyResolver(deps.ProofBindingKeys); ok && r.Revocation == nil {
		return fmt.Errorf("dependencies.proof_binding_keys: X5CProofBindingKeyResolver.Revocation is required under AssuranceProduction: %s", choices)
	}
	return nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented x5c chain against an in-memory Roots pool never
// touches the network, so LiveFetchHardened is unconditionally true.
func (r X5CProofBindingKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
