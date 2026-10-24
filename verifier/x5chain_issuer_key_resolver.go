package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// X5ChainIssuerKeyResolver implements MdocIssuerKeyResolver by
// validating a presented "mso_mdoc" credential's own IssuerAuth
// "x5chain" COSE header (RFC 9360 §2) against Roots — the mdoc analog
// of X5CIssuerKeyResolver (its own doc comment explains the shared
// rationale: HAIP's own trust model wants a leaf issued by a separate
// CA, and a self-signed leaf is rejected even if that exact
// certificate is itself a configured root). Revocation is checked as
// X5CIssuerKeyResolver checks it: a document is accepted only through a
// verified path on which no certificate — the document signer's or an
// intermediate's — is revoked. ISO/IEC 18013-5 has every document
// signer certificate name the IACA's CRL distribution point (Annex B,
// B.1), so certrevocation.CRLs with each IACA's current CRL is the
// usual Revocation.
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
	// where the anchors are shared. nil means
	// mdoc.DefaultDocumentSignerPolicy, which refuses the certificates
	// an IACA issues for other jobs (an OCSP signer's, one whose key
	// usage doesn't allow digital signatures, one whose extended key
	// usage leaves out the mDL document signer's, such as a reader
	// authentication certificate); a LeafPolicy that's set replaces it.
	LeafPolicy func(leaf *x509.Certificate, chains [][]*x509.Certificate) error
	// Revocation decides whether a certificate on a verified path — the
	// document signer's, or an intermediate CA's — has been revoked,
	// so a document signer whose key was stolen isn't accepted until
	// its certificate expires. REQUIRED, with no default: pass
	// certrevocation.CRLs{...} with your IACAs' current CRLs, your own
	// certrevocation.Checker (OCSP, for example), or
	// certrevocation.NoCheck{} to decline — see its doc comment for
	// when that's acceptable.
	Revocation certrevocation.Checker
}

// Validate reports a resolver that can't verify anything as configured:
// one without Revocation, or whose Revocation is itself incomplete (a
// certrevocation.CRLs without Lists). VerifyResponse, NewTransactions
// and mdocdcapi.VerifyResponse call it on the resolvers they're given,
// so the mistake shows before any document does; ResolveMdocIssuerKey
// and ResolveMdocIssuerChains refuse to resolve without it passing too.
func (r X5ChainIssuerKeyResolver) Validate() error {
	return validateRevocation("X5ChainIssuerKeyResolver", r.Revocation)
}

// leafPolicy is LeafPolicy, or mdoc.DefaultDocumentSignerPolicy.
func (r X5ChainIssuerKeyResolver) leafPolicy() func(*x509.Certificate, [][]*x509.Certificate) error {
	if r.LeafPolicy != nil {
		return r.LeafPolicy
	}
	return mdoc.DefaultDocumentSignerPolicy
}

// ResolveMdocIssuerKey implements MdocIssuerKeyResolver.
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerKey(ctx context.Context, x5chain [][]byte, docType string) (crypto.PublicKey, oid4vci.COSEAlg, error) {
	leaf, _, err := r.verify(ctx, x5chain, docType)
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
// certificate paths x5chain verifies on under Roots that LeafPolicy
// approves each on its own (certchain.ApprovedChains) and Revocation
// passes: the issuer chain CheckMdocIssuer picks is one of them.
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerChains(ctx context.Context, x5chain [][]byte, docType string) ([][]*x509.Certificate, error) {
	_, chains, err := r.verify(ctx, x5chain, docType)
	return chains, err
}

// verify verifies x5chain under docType's roots: the leaf, and its
// paths that LeafPolicy approves and Revocation passes.
func (r X5ChainIssuerKeyResolver) verify(ctx context.Context, x5chain [][]byte, docType string) (*x509.Certificate, [][]*x509.Certificate, error) {
	if err := r.Validate(); err != nil {
		return nil, nil, err
	}
	roots, err := r.rootsFor(docType)
	if err != nil {
		return nil, nil, err
	}
	return certchain.VerifyTrustedChainsAt(ctx, x5chain, roots, r.leafPolicy(), r.Revocation, verificationTime(ctx))
}

// rootsFor is the trust anchors a document of docType must chain to:
// RootsByDocType's for a type it names, else Roots.
func (r X5ChainIssuerKeyResolver) rootsFor(docType string) (*x509.CertPool, error) {
	if roots, ok := r.RootsByDocType[docType]; ok {
		// A type named with no roots falls back to none: Roots weren't
		// chosen for it.
		if roots == nil {
			return nil, fmt.Errorf("verifier: no trust anchors for document type %q", docType)
		}
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
