package walletprovider

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// InstanceKey is an instance key: the key a Wallet Attestation's cnf
// names, which the wallet uses for one issuance (HAIP 1.0 §4.4.1: a
// Wallet Attestation isn't reused across Credential Issuers), so
// issuers see a key, and a status list index, of that issuance alone.
// Platform evidence vouches for it the first time the instance asks
// for a Wallet Attestation for it; the provider then records it
// against the instance and reserves its status list index, which every
// Wallet Attestation for it, and every Key Attestation issued with it,
// references. Suspending or revoking the instance sets the status of
// each of its instance keys.
//
// The provider knows which instance keys belong to which instance;
// issuers don't. Keep the records as private as the instances.
type InstanceKey struct {
	// Thumbprint is the key's RFC 7638 JWK SHA-256 thumbprint,
	// base64url, which identifies the record, and Key the key as a
	// public JWK.
	Thumbprint string
	Key        json.RawMessage

	// InstanceID is the instance the key belongs to.
	InstanceID string

	// Status is the key's index in the provider's status list.
	Status statuslist.StatusListRef

	// SecurityLevel is where the key's evidence showed it's held, and
	// Binding how the evidence vouched for it.
	SecurityLevel SecurityLevel
	Binding       KeyBinding

	CreatedAt time.Time
}

// clone returns a copy of k sharing no memory with it.
func (k InstanceKey) clone() InstanceKey {
	k.Key = slices.Clone(k.Key)
	return k
}

// InstanceKeyStore keeps instance keys. A production store is durable
// and shared by every process serving the provider. Records are never
// changed once created.
type InstanceKeyStore interface {
	// Get returns the instance key with thumbprint, or an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, thumbprint string) (InstanceKey, error)

	// Create stores k, or returns an error wrapping ErrExists if an
	// instance key with its Thumbprint is stored, whatever its instance:
	// one key belongs to one instance. The check and the store are one
	// atomic step, as a UNIQUE constraint makes them.
	Create(ctx context.Context, k InstanceKey) error

	// List returns up to limit of the instance keys of the instance
	// instanceID whose thumbprints sort after after (every one when
	// after is empty), in ascending thumbprint order: a page of a walk
	// over the instance's keys, to set their statuses. limit is
	// positive.
	List(ctx context.Context, instanceID, after string, limit int) ([]InstanceKey, error)
}

// MemoryInstanceKeyStore is an InstanceKeyStore held in memory, safe
// for concurrent use; its zero value is ready to use. It isn't durable:
// a restart forgets every instance key, and their status indices stay
// reserved in the IndexStore. For tests and demos.
type MemoryInstanceKeyStore struct {
	mu   sync.Mutex
	keys map[string]InstanceKey
}

var _ InstanceKeyStore = (*MemoryInstanceKeyStore)(nil)

// Get implements InstanceKeyStore.
func (s *MemoryInstanceKeyStore) Get(ctx context.Context, thumbprint string) (InstanceKey, error) {
	if err := ctx.Err(); err != nil {
		return InstanceKey{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.keys[thumbprint]
	if !ok {
		return InstanceKey{}, ErrNotFound
	}
	return k.clone(), nil
}

// Create implements InstanceKeyStore.
func (s *MemoryInstanceKeyStore) Create(ctx context.Context, k InstanceKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.Thumbprint]; ok {
		return ErrExists
	}
	if s.keys == nil {
		s.keys = make(map[string]InstanceKey)
	}
	s.keys[k.Thumbprint] = k.clone()
	return nil
}

// List implements InstanceKeyStore.
func (s *MemoryInstanceKeyStore) List(ctx context.Context, instanceID, after string, limit int) ([]InstanceKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var thumbprints []string
	for tp, k := range s.keys {
		if k.InstanceID == instanceID && tp > after {
			thumbprints = append(thumbprints, tp)
		}
	}
	sort.Strings(thumbprints)
	if len(thumbprints) > limit {
		thumbprints = thumbprints[:max(limit, 0)]
	}
	out := make([]InstanceKey, len(thumbprints))
	for i, tp := range thumbprints {
		out[i] = s.keys[tp].clone()
	}
	return out, nil
}
