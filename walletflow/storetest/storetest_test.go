package storetest_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/storetest"
)

func TestMemoryCredentialStore(t *testing.T) {
	storetest.TestCredentialStoreContract(t, func() walletflow.CredentialStore { return walletflow.NewMemoryCredentialStore() })
}

func TestMemoryAuthorizationStore(t *testing.T) {
	storetest.TestAuthorizationStoreContract(t, func() walletflow.AuthorizationStore { return walletflow.NewMemoryAuthorizationStore() })
}

func TestMemoryGrantStore(t *testing.T) {
	storetest.TestGrantStoreContract(t, func() walletflow.GrantStore { return walletflow.NewMemoryGrantStore() })
}

func TestMemoryDeferredStore(t *testing.T) {
	storetest.TestDeferredStoreContract(t, func() walletflow.DeferredStore { return walletflow.NewMemoryDeferredStore() })
}

func TestMemoryKeyStore(t *testing.T) {
	storetest.TestKeyStoreContract(t, func() walletflow.KeyStore { return walletflow.NewMemoryKeyStore() })
}

// A memory store's handles are the store itself: every Wallet sharing
// it is in one process.

func TestSharedMemoryCredentialStore(t *testing.T) {
	storetest.TestSharedCredentialStoreContract(t, func() func() walletflow.CredentialStore {
		s := walletflow.NewMemoryCredentialStore()
		return func() walletflow.CredentialStore { return s }
	})
}

func TestSharedMemoryAuthorizationStore(t *testing.T) {
	storetest.TestSharedAuthorizationStoreContract(t, func() func() walletflow.AuthorizationStore {
		s := walletflow.NewMemoryAuthorizationStore()
		return func() walletflow.AuthorizationStore { return s }
	})
}

func TestSharedMemoryGrantStore(t *testing.T) {
	storetest.TestSharedGrantStoreContract(t, func() func() walletflow.GrantStore {
		s := walletflow.NewMemoryGrantStore()
		return func() walletflow.GrantStore { return s }
	})
}
