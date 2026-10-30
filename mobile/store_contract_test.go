package mobile

import (
	"bytes"
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
	s.put(id, record)
	return nil
}

func (s *goCredentialStore) put(id string, record []byte) {
	if _, ok := s.records[id]; !ok {
		s.order = append(s.order, id)
	}
	s.records[id] = record
}

func (s *goCredentialStore) CompareAndSwap(id string, expected, record []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.records[id]
	switch {
	case !bytes.Equal(prev, expected):
	case len(record) == 0:
		s.delete(id)
	default:
		s.put(id, record)
	}
	return prev, nil
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
	s.delete(id)
	return nil
}

func (s *goCredentialStore) delete(id string) {
	if _, ok := s.records[id]; ok {
		delete(s.records, id)
		s.order = slices.DeleteFunc(s.order, func(o string) bool { return o == id })
	}
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

// Each handle is an adapter of its own over one app store, as the app
// and its extension each have over the files they share: the store's
// CompareAndSwap alone keeps their updates and consumes atomic.

func TestSharedCredentialStoreContract(t *testing.T) {
	storetest.TestSharedCredentialStoreContract(t, func() func() walletflow.CredentialStore {
		cs := sharedNativeStore()
		_ = cs.Delete("other-credential")
		return func() walletflow.CredentialStore { return credentialStore{cs} }
	})
}

func TestSharedAuthorizationStoreContract(t *testing.T) {
	storetest.TestSharedAuthorizationStoreContract(t, func() func() walletflow.AuthorizationStore {
		cs := sharedNativeStore()
		_ = cs.Delete(authorizationStoreID("other-state"))
		return func() walletflow.AuthorizationStore { return authorizationStore{cs} }
	})
}

func TestSharedGrantStoreContract(t *testing.T) {
	storetest.TestSharedGrantStoreContract(t, func() func() walletflow.GrantStore {
		cs := sharedNativeStore()
		_ = cs.Delete(grantStoreID("other-grant"))
		return func() walletflow.GrantStore { return grantStore{cs} }
	})
}

// churningStore is an app store that another process writes to between
// every read and swap of a record.
type churningStore struct{ *goCredentialStore }

func (s churningStore) CompareAndSwap(id string, expected, record []byte) ([]byte, error) {
	raw, _ := s.Get(id)
	_ = s.Put(id, append(slices.Clone(raw), '\n'))
	return s.goCredentialStore.CompareAndSwap(id, expected, record)
}

// An update that keeps losing to another process gives up, as a
// platform error, storing nothing of its own.
func TestCredentialStoreUpdate_GivesUpOnChurn(t *testing.T) {
	ctx := context.Background()
	cs := churningStore{newGoCredentialStore()}
	at := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	if err := (credentialStore{cs}).Put(ctx, walletflow.StoredCredential{ID: "c", Format: "dc+sd-jwt", Credential: "x", HolderKeyID: "k", ReceivedAt: at}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := credentialStore{cs}.Update(ctx, "c", func(c *walletflow.StoredCredential) error {
		calls++
		c.HolderKeyID = "changed"
		return nil
	})
	if code(err) != CodePlatform || calls != maxSwapAttempts {
		t.Errorf("Update against constant churn = %v after %d calls; want a platform error after %d", err, calls, maxSwapAttempts)
	}
	if c, _ := (credentialStore{cs}).Get(ctx, "c"); c.HolderKeyID != "k" {
		t.Errorf("the update was stored: holder key %q", c.HolderKeyID)
	}
}
