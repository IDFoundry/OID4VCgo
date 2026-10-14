package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
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
	// against, for a document type RootsByDocType doesn't name. Leave it
	// nil, with RootsByDocType set, to accept only the document types it
	// names. One of the two is REQUIRED.
	Roots *x509.CertPool

	// RootsByDocType, OPTIONAL, are the trust anchors for each document
	// type: a document of a type it names must chain to that type's
	// anchors, not to Roots. Without it, every anchor in Roots may sign
	// every document type — a PID issuer's an mDL, say — so where the
	// anchors come from different ecosystems, name each one's types
	// here.
	RootsByDocType map[string]*x509.CertPool
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
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerKey(_ context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	roots, err := r.rootsFor(docType)
	if err != nil {
		return nil, 0, err
	}
	leaf, err := certchain.VerifyLeafWithPolicy(x5chain, roots, r.LeafPolicy)
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

// ResolveMdocIssuerChains implements MdocIssuerChainResolver: the
// certificate paths x5chain verifies on, under Roots and LeafPolicy.
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerChains(_ context.Context, x5chain [][]byte, docType string) ([][]*x509.Certificate, error) {
	roots, err := r.rootsFor(docType)
	if err != nil {
		return nil, err
	}
	leaf, chains, err := certchain.VerifyChains(x5chain, roots)
	if err != nil {
		return nil, err
	}
	if r.LeafPolicy != nil {
		if err := r.LeafPolicy(leaf, chains); err != nil {
			return nil, err
		}
	}
	return chains, nil
}

// rootsFor is the trust anchors a document of docType must chain to:
// RootsByDocType's for a type it names, else Roots.
func (r X5ChainIssuerKeyResolver) rootsFor(docType string) (*x509.CertPool, error) {
	if roots, ok := r.RootsByDocType[docType]; ok && roots != nil {
		return roots, nil
	}
	if r.Roots == nil {
		if len(r.RootsByDocType) > 0 {
			return nil, fmt.Errorf("verifier: no trust anchors for document type %q", docType)
		}
		return nil, errors.New("verifier: X5ChainIssuerKeyResolver needs Roots or RootsByDocType")
	}
	return r.Roots, nil
}
