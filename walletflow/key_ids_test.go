package walletflow_test

import (
	"context"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// oneIDKeys is a KeyStore that breaks its contract: every key it makes
// has the same ID.
type oneIDKeys struct {
	*walletflow.MemoryKeyStore
	last walletflow.Key
}

type renamedKey struct{ walletflow.Key }

func (renamedKey) ID() string { return "same" }

func (s *oneIDKeys) NewKey(ctx context.Context, purpose walletflow.KeyPurpose) (walletflow.Key, error) {
	k, err := s.MemoryKeyStore.NewKey(ctx, purpose)
	if err != nil {
		return nil, err
	}
	s.last = renamedKey{k}
	return s.last, nil
}

func (s *oneIDKeys) Key(_ context.Context, id string) (walletflow.Key, error) {
	if s.last == nil || id != "same" {
		return nil, walletflow.ErrNotFound
	}
	return s.last, nil
}

// A batch received with a KeyStore that gives every key one ID leaves
// later copies no key to bind: the credential is refused, and the
// wallet doesn't panic.
func TestRequestCredentials_KeyStoreReusingIDs(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots, Development: true,
	}, walletflow.Dependencies{
		Keys: &oneIDKeys{MemoryKeyStore: walletflow.NewMemoryKeyStore()}, Credentials: f.store, Provider: f.env.Provider, HTTP: f.env.HTTP,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(ctx) }()
	authorize(t, f, s)
	result, err := s.RequestCredentials(ctx)
	if err == nil && len(result.Failed) == 0 {
		t.Fatalf("received %d credentials with one key ID for every key", len(result.Credentials))
	}
	got := ""
	if err != nil {
		got = err.Error()
	} else {
		got = result.Failed[0].Err.Error()
	}
	if !strings.Contains(got, "no holder key is left") {
		t.Errorf("refused with %q, want no holder key left", got)
	}
}
