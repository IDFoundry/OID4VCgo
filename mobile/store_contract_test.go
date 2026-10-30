package mobile

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/storetest"
)

// goCredentialStore is a CredentialStore in memory, as the app's would
// be.
type goCredentialStore struct {
	mu        sync.Mutex
	records   map[string][]byte
	order     []string
	ephemeral bool // says it isn't Durable
}

func newGoCredentialStore() *goCredentialStore {
	return &goCredentialStore{records: map[string][]byte{}}
}

func (s *goCredentialStore) Durable() bool { return !s.ephemeral }

func (s *goCredentialStore) Put(id string, record []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; !ok {
		s.order = append(s.order, id)
	}
	s.records[id] = record
	return nil
}

func (s *goCredentialStore) Get(id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.records[id], nil
}

func (s *goCredentialStore) List() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]json.RawMessage, 0, len(s.order))
	for _, id := range s.order {
		all = append(all, s.records[id])
	}
	return json.Marshal(all)
}

func (s *goCredentialStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[id]; ok {
		delete(s.records, id)
		s.order = slices.DeleteFunc(s.order, func(o string) bool { return o == id })
	}
	return nil
}

// sharedNativeStore is the app's one CredentialStore, holding a record
// of every kind the adapters keep in it — so each adapter's contract
// also checks that it neither lists nor finds the others'.
func sharedNativeStore() *goCredentialStore {
	ctx := context.Background()
	cs := newGoCredentialStore()
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	for _, err := range []error{
		credentialStore{cs}.Put(ctx, walletflow.StoredCredential{ID: "other-credential", Format: "dc+sd-jwt", Credential: "c", HolderKeyID: "k", ReceivedAt: at}),
		deferredStore{cs}.PutDeferred(ctx, walletflow.PendingDeferred{ID: "other-deferred", DeferredAt: at}),
		authorizationStore{cs}.PutAuthorization(ctx, walletflow.PendingAuthorization{State: "other-state", Session: json.RawMessage(`{}`), ExpiresAt: at}),
		grantStore{cs}.PutGrant(ctx, walletflow.RefreshGrant{ID: "other-grant", RefreshToken: fapi.NewSecret("r"), CreatedAt: at}),
	} {
		if err != nil {
			panic("seed the shared store: " + err.Error())
		}
	}
	return cs
}

// The adapters over the app's CredentialStore, and over its KeyStore,
// meet walletflow's store contracts — with the other kinds of record
// beside each.

func TestCredentialStoreContract(t *testing.T) {
	storetest.TestCredentialStoreContract(t, func() walletflow.CredentialStore {
		cs := sharedNativeStore()
		_ = cs.Delete("other-credential")
		return credentialStore{cs}
	})
}

func TestDeferredStoreContract(t *testing.T) {
	storetest.TestDeferredStoreContract(t, func() walletflow.DeferredStore {
		cs := sharedNativeStore()
		_ = cs.Delete(deferredStoreID("other-deferred"))
		return deferredStore{cs}
	})
}

func TestAuthorizationStoreContract(t *testing.T) {
	storetest.TestAuthorizationStoreContract(t, func() walletflow.AuthorizationStore {
		cs := sharedNativeStore()
		_ = cs.Delete(authorizationStoreID("other-state"))
		return authorizationStore{cs}
	})
}

func TestGrantStoreContract(t *testing.T) {
	storetest.TestGrantStoreContract(t, func() walletflow.GrantStore {
		cs := sharedNativeStore()
		_ = cs.Delete(grantStoreID("other-grant"))
		return grantStore{cs}
	})
}

func TestKeyStoreContract(t *testing.T) {
	storetest.TestKeyStoreContract(t, func() walletflow.KeyStore { return keyStore{ks: newGoKeyStore()} })
}
