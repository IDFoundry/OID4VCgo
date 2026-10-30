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
