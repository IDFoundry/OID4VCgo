package verifier

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
	"github.com/idfoundry/oid4vcgo/internal/cose"
)

// X5ChainIssuerKeyResolver implements MdocIssuerKeyResolver by
// validating a presented "mso_mdoc" credential's own IssuerAuth
// "x5chain" COSE header (RFC 9360 §2) against Roots — the mdoc analog
// of X5CIssuerKeyResolver (its own doc comment explains the shared
// rationale: HAIP's own trust model wants a leaf issued by a separate
// CA, and a self-signed leaf is rejected even if that exact
// certificate is itself a configured root).
type X5ChainIssuerKeyResolver struct {
	// Roots is the trust anchor set a presented x5chain must validate
	// against. REQUIRED.
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

// ResolveMdocIssuerKey implements MdocIssuerKeyResolver.
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerKey(_ context.Context, x5chain [][]byte, _ string) (crypto.PublicKey, cose.Alg, error) {
	leaf, err := certchain.VerifyLeafWithPolicy(x5chain, r.Roots, r.LeafPolicy)
	if err != nil {
		return nil, 0, err
	}
	alg, err := mdocAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, 0, err
	}
	return leaf.PublicKey, alg, nil
}

// Capabilities implements KeySourceAssurance: validating an
// already-presented certificate chain against an in-memory CertPool
// never touches the network.
func (r X5ChainIssuerKeyResolver) Capabilities() KeySourceCapabilities {
	return KeySourceCapabilities{LiveFetchHardened: true}
}
