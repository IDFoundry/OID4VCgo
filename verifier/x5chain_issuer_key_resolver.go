package verifier

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"

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
	if len(x5chain) == 0 {
		return nil, 0, fmt.Errorf("verifier: IssuerAuth has no x5chain")
	}
	certs := make([]*x509.Certificate, 0, len(x5chain))
	for i, der := range x5chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, 0, fmt.Errorf("verifier: parse x5chain[%d]: %w", i, err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]

	if isSelfSigned(leaf) {
		return nil, 0, fmt.Errorf("verifier: x5chain leaf certificate must not be self-signed")
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	// ExtKeyUsageAny is deliberate — see X5CIssuerKeyResolver's own
	// identical choice and doc comment (verifier/x5c_issuer_key_resolver.go)
	// for why: no standard EKU exists for this purpose, and Roots is
	// the actual trust boundary here, not the EKU.
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         r.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, 0, fmt.Errorf("verifier: x5chain does not verify against a trusted root: %w", err)
	}

	alg, err := mdocAlgForKey(leaf.PublicKey)
	if err != nil {
		return nil, 0, err
	}
	return leaf.PublicKey, alg, nil
}
