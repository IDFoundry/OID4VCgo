package verifier_test

import (
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestContractSuitesAgainstX5CResolvers proves this package's own
// X5CIssuerKeyResolver/X5ChainIssuerKeyResolver satisfy the trust
// contract TestX5CTrustContract/TestX5ChainTrustContract check —
// dogfooding the same exported functions a caller building a
// similarly-shaped resolver would run against their own factory.
func TestContractSuitesAgainstX5CResolvers(t *testing.T) {
	verifier.TestX5CTrustContract(t, func(roots *x509.CertPool) verifier.SDJWTVCIssuerKeyResolver {
		return verifier.X5CIssuerKeyResolver{Roots: roots}
	})
	verifier.TestX5ChainTrustContract(t, func(roots *x509.CertPool) verifier.MdocIssuerKeyResolver {
		return verifier.X5ChainIssuerKeyResolver{Roots: roots}
	})
}
