package issuer_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

// TestContractSuitesAgainstStorage runs every contract test in this
// package against storage's own bundled (development/testing-only, see
// storage/doc.go) implementations — proving the contracts are
// satisfiable at all, and giving this repo's own conformance harness
// (which wires these in under AssuranceDevelopment) the same
// correctness coverage a real backend's own implementation should run
// via these same exported functions.
func TestContractSuitesAgainstStorage(t *testing.T) {
	issuer.TestNonceStoreContract(t, func() issuer.NonceStore { return storage.NewNonceStore() })
	issuer.TestDPoPNonceStoreContract(t, func() issuer.DPoPNonceStore { return storage.NewDPoPNonceStore() })
	issuer.TestPreAuthorizedCodeStoreContract(t, func() issuer.PreAuthorizedCodeStore { return storage.NewPreAuthorizedCodeStore() })
	issuer.TestDPoPReplayCheckerContract(t, func() issuer.DPoPReplayChecker { return storage.NewDPoPReplayChecker() })
	issuer.TestCredentialOfferStoreContract(t, func() issuer.CredentialOfferStore { return storage.NewCredentialOfferStore() })
	issuer.TestNotificationStoreContract(t, func() issuer.NotificationStore { return storage.NewNotificationStore() })
	issuer.TestDeferredTransactionStoreContract(t, func(t *testing.T, transactionID string, record issuer.DeferredTransactionRecord) issuer.DeferredTransactionStore {
		t.Helper()
		s := storage.NewDeferredTransactionStore()
		if err := s.Put(t.Context(), transactionID, record); err != nil {
			t.Fatalf("Put: %v", err)
		}
		return s
	})
}

// TestContractSuitesAgainstFakes runs every contract test in this
// package against this package's own test fakes — the same fakes
// every other *_test.go file in this package already exercises the
// issuer role's own logic against, now also proven to satisfy each
// store interface's documented contract in their own right.
func TestContractSuitesAgainstFakes(t *testing.T) {
	issuer.TestNonceStoreContract(t, func() issuer.NonceStore { return newFakeNonceStore() })
	issuer.TestDPoPNonceStoreContract(t, func() issuer.DPoPNonceStore { return newFakeDPoPNonceStore() })
	issuer.TestPreAuthorizedCodeStoreContract(t, func() issuer.PreAuthorizedCodeStore { return newFakePreAuthorizedCodeStore() })
	issuer.TestDPoPReplayCheckerContract(t, func() issuer.DPoPReplayChecker { return newFakeDPoPReplayChecker() })
	issuer.TestCredentialOfferStoreContract(t, func() issuer.CredentialOfferStore { return newFakeCredentialOfferStore() })
	issuer.TestNotificationStoreContract(t, func() issuer.NotificationStore { return newFakeNotificationStore() })
	issuer.TestDeferredTransactionStoreContract(t, func(t *testing.T, transactionID string, record issuer.DeferredTransactionRecord) issuer.DeferredTransactionStore {
		t.Helper()
		f := newFakeDeferredTransactionStore()
		f.put(transactionID, record)
		return f
	})
}
