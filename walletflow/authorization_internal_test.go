package walletflow

import (
	"testing"

	"github.com/idfoundry/fapigo/storage"
)

// The SessionStore walletflow gives fapigo/client, over its
// AuthorizationStore, meets FAPIgo's own contract: single-use, atomic
// consume included.
func TestSessionStoreContract(t *testing.T) {
	storage.TestSessionStoreContract(t, func() storage.SessionStore {
		w, err := New(Config{Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore()})
		if err != nil {
			t.Fatal(err)
		}
		return &sessionStore{w: w}
	})
}
