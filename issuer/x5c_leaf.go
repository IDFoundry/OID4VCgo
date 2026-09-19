package issuer

import (
	"crypto/x509"
	"fmt"

	"github.com/idfoundry/oid4vcgo/internal/certchain"
)

// resolveX5CLeaf extracts x5c (RFC 7515 §4.1.6: standard-base64-encoded
// DER certificates, leaf first, as a decoded JSON array) and verifies
// it against roots, requiring at least one entry — shared by
// X5CAttestationVerifier and X5CProofBindingKeyResolver, which differ
// only in how they got x5c from their own caller's own wire shape (a
// KeyAttestation's own []string vs a raw JOSE header's own []any).
func resolveX5CLeaf(x5c []any, roots *x509.CertPool) (*x509.Certificate, error) {
	if len(x5c) == 0 {
		return nil, fmt.Errorf("issuer: x5c must be a non-empty array")
	}
	ders, err := certchain.DERsFromBase64(x5c)
	if err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	return certchain.VerifyLeaf(ders, roots)
}
