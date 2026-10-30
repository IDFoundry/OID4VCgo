package walletapp

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/storetest"
)

// The demo's software KeyStore meets walletflow's KeyStore contract.
func TestSoftwareKeysContract(t *testing.T) {
	storetest.TestKeyStoreContract(t, func() walletflow.KeyStore { return newSoftwareKeys() })
}
