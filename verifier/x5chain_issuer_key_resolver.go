package verifier

import (
	"context"
	"crypto"
	"crypto/x509"

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
}

// ResolveMdocIssuerKey implements MdocIssuerKeyResolver.
func (r X5ChainIssuerKeyResolver) ResolveMdocIssuerKey(_ context.Context, x5chain [][]byte, _ string) (crypto.PublicKey, cose.Alg, error) {
	leaf, err := verifyLeafCertChain(x5chain, r.Roots)
	if err != nil {
		return nil, 0, err
	}
	alg, err := mdocAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, 0, err
	}
	return leaf.PublicKey, alg, nil
}
