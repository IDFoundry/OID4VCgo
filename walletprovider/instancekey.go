package walletprovider

import (
	"context"
	"encoding/json"
	"errors"
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
// references, until a later period: the key then gets an index on that
// period's lists (Config.StatusListPeriod). Suspending or revoking the
// instance sets the status of each of its instance keys. A key unused
// for Config.InstanceKeyRetention may be deleted (RetainUntil): it's
// then unknown, and needs evidence again, as a new key does.
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

	// Status is the key's index on one of the provider's status lists,
	// the one attestations name, and PreviousStatus the one it had in
	// the previous period, which attestations issued then may still
	// name, or the zero StatusListRef.
	Status         statuslist.StatusListRef
	PreviousStatus statuslist.StatusListRef

	// SecurityLevel is where the key's evidence showed it's held, and
	// Binding how the evidence vouched for it.
	SecurityLevel SecurityLevel
	Binding       KeyBinding

	CreatedAt time.Time

	// RetainUntil is when the store may delete the record: the start of
	// Status's period plus Config.InstanceKeyRetention, set each time
	// the provider records or moves the key. By then no live
	// attestation names the key, nor will, but a later request for it
	// finds it unknown. Zero, as in a record from before retention,
	// keeps it until it moves.
	RetainUntil time.Time

	// Revision is the store's version of the record: Create stores 1,
	// and each Update one more. Update compares it to detect a
	// concurrent change.
	Revision uint64
}

// clone returns a copy of k sharing no memory with it.
func (k InstanceKey) clone() InstanceKey {
	k.Key = slices.Clone(k.Key)
	return k
}

// InstanceKeyStore keeps instance keys. A production store is durable
// and shared by every process serving the provider, as the
// github.com/idfoundry/oid4vcgo/sqlstore module's
// DB.WalletProviderInstanceKeys is. A record changes only when the
// key moves to a later period's status lists (Update). A store may
// delete a record once its RetainUntil, if set, has passed, and should,
// to keep the records of keys no wallet uses from piling up: nothing
// else deletes one. Until it does, the record serves as before: using
// the key moves it, and sets a later RetainUntil.
type InstanceKeyStore interface {
	// Get returns the instance key with thumbprint, or an error wrapping
	// ErrNotFound.
	Get(ctx context.Context, thumbprint string) (InstanceKey, error)

	// Create stores k with Revision 1 (whatever k.Revision is), or
	// returns an error wrapping ErrExists if an instance key with its
	// Thumbprint is stored, whatever its instance: one key belongs to
	// one instance. The check and the store are one atomic step, as a
	// UNIQUE constraint makes them.
	Create(ctx context.Context, k InstanceKey) error

	// Update replaces the stored instance key with k's Thumbprint by k,
	// with Revision k.Revision+1, if the stored one's Revision is
	// k.Revision — one atomic compare-and-swap, as an UPDATE ... WHERE
	// revision = ? is. It returns an error wrapping ErrConflict, and
	// changes nothing, if the stored Revision differs, and ErrNotFound
	// if no instance key has the Thumbprint. It refuses, changing
	// nothing, a k of another instance than the stored one's.
	Update(ctx context.Context, k InstanceKey) error

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
// reserved in the IndexStore. Create drops the records whose
// RetainUntil is before the new one's CreatedAt. For tests and demos.
type MemoryInstanceKeyStore struct {
	mu   sync.Mutex
	keys map[string]InstanceKey
	// swept is how many records were left by the last sweep: the next
	// runs once there are twice as many, as MemoryChallengeStore's does.
	swept int
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
	if len(s.keys) >= 2*s.swept+64 {
		for tp, stored := range s.keys {
			if !stored.RetainUntil.IsZero() && stored.RetainUntil.Before(k.CreatedAt) {
				delete(s.keys, tp)
			}
		}
		s.swept = len(s.keys)
	}
	if _, ok := s.keys[k.Thumbprint]; ok {
		return ErrExists
	}
	if s.keys == nil {
		s.keys = make(map[string]InstanceKey)
	}
	k = k.clone()
	k.Revision = 1
	s.keys[k.Thumbprint] = k
	return nil
}

// Update implements InstanceKeyStore.
func (s *MemoryInstanceKeyStore) Update(ctx context.Context, k InstanceKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.keys[k.Thumbprint]
	switch {
	case !ok:
		return ErrNotFound
	case stored.InstanceID != k.InstanceID:
		return errors.New("walletprovider: an update can't move an instance key to another instance")
	case stored.Revision != k.Revision:
		return ErrConflict
	}
	k = k.clone()
	k.Revision++
	s.keys[k.Thumbprint] = k
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
