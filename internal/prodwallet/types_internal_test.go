package prodwallet

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

func TestStoresDependenciesAndClose(t *testing.T) {
	closed := false
	s := &Stores{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(),
		Authorizations: walletflow.NewMemoryAuthorizationStore(), Grants: walletflow.NewMemoryGrantStore(),
		Deferred: walletflow.NewMemoryDeferredStore(),
		close:    func() error { closed = true; return nil },
	}
	deps := s.Dependencies(walletflow.Dependencies{})
	if deps.Keys != s.Keys || deps.Credentials != s.Credentials || deps.Authorizations != s.Authorizations ||
		deps.Grants != s.Grants || deps.Deferred != s.Deferred {
		t.Fatalf("Dependencies = %+v", deps)
	}
	if err := s.Close(); err != nil || !closed {
		t.Fatalf("Close: %v, closed %v", err, closed)
	}
	if err := (&Stores{}).Close(); err != nil {
		t.Fatal(err)
	}
}
