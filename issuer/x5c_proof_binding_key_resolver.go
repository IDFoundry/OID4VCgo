package issuer

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
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
	// where the anchors are shared.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
}

// ResolveProofBindingKey implements ProofBindingKeyResolver.
func (r X5CProofBindingKeyResolver) ResolveProofBindingKey(_ context.Context, header map[string]any) (crypto.PublicKey, oid4vci.JOSEAlg, error) {
	raw, ok := header["x5c"]
	if !ok {
		return nil, "", fmt.Errorf("issuer: proof header has no x5c")
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, "", fmt.Errorf("issuer: proof x5c header is not an array")
	}
	leaf, err := resolveX5CLeaf(entries, r.Roots, r.LeafPolicy)
	if err != nil {
		return nil, "", err
	}
	alg, err := algForKey(leaf.PublicKey)
	if err != nil {
		return nil, "", err
	}
	return leaf.PublicKey, alg, nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented x5c chain against an in-memory Roots pool never
// touches the network, so LiveFetchHardened is unconditionally true.
func (r X5CProofBindingKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
