package verifier_test

import (
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

// TestContractSuitesAgainstX5CResolvers proves this package's own
// X5CIssuerKeyResolver/X5ChainIssuerKeyResolver satisfy the trust
// contract TestX5CTrustContract/TestX5ChainTrustContract check —
// dogfooding the same exported functions a caller building a
// similarly-shaped resolver would run against their own factory.
func TestContractSuitesAgainstX5CResolvers(t *testing.T) {
	verifiertest.TestX5CTrustContract(t, func(roots *x509.CertPool) verifier.SDJWTVCIssuerKeyResolver {
		return verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	})
	verifiertest.TestX5ChainTrustContract(t, func(roots *x509.CertPool) verifier.MdocIssuerKeyResolver {
		return verifier.X5ChainIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	})
}

// TestContractSuiteAgainstTransactionStore runs TestTransactionStoreContract
// against storage's in-memory store.
func TestContractSuiteAgainstTransactionStore(t *testing.T) {
	verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore {
		return storage.NewVerifierTransactionStore()
	})
}
