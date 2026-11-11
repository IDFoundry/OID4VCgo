package walletprovider

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"sync"
	"time"
)

// State is a wallet instance's state.
type State string

const (
	// StateActive: the provider attests for the instance.
	StateActive State = "active"

	// StateSuspended: the provider attests nothing for the instance,
	// and the status of each of its instance keys is SUSPENDED, until
	// it's resumed.
	StateSuspended State = "suspended"

	// StateRevoked: the provider attests nothing for the instance, and
	// the status of each of its instance keys is INVALID, for good.
	StateRevoked State = "revoked"
)

// EvidenceSummary is what an instance's registration evidence proved.
type EvidenceSummary struct {
	// Kind is the evidence's Kind, which names its EvidenceVerifier.
	Kind string

	Platform Platform

	// SecurityLevel is where the registration key is held, and Binding
	// how the evidence vouched for it.
	SecurityLevel SecurityLevel
	Binding       KeyBinding

	AppID        string
	AppVersion   uint64
	BootState    BootState
	DeviceLocked bool
}

// Instance is a registered wallet instance (HAIP 1.0's Wallet
// Instance): one installation of the app on one device, identified by
// its registration key, which signs every request it makes after
// registering (SignRequest). The registration key is the provider's
// alone: no attestation names it, and the instance has no status of
// its own. A Wallet Attestation's cnf names one of the instance's
// instance keys (InstanceKey), a fresh one per issuance, each with its
// own status, so issuers can't link one issuance to another.
type Instance struct {
	// ID is the provider's random identifier for the instance.
	ID string

	// KeyThumbprint is the registration key's RFC 7638 JWK SHA-256
	// thumbprint, base64url, and Key the key as a public JWK.
	KeyThumbprint string
	Key           json.RawMessage

	// Evidence is what the registration evidence proved.
	Evidence EvidenceSummary

	// Credential is the registration verifier's state for the instance
	// (VerifiedEvidence.Credential): an App Attest key. Opaque here.
	Credential []byte

	// CredentialID identifies the credential (VerifiedEvidence.CredentialID):
	// an App Attest key's key ID, base64, as DCAppAttestService gives
	// it. Empty when the registration verifier reported none, as an
	// Android one doesn't. No two instances have the same non-empty one.
	CredentialID string

	// Counter is the instance's signature counter (App Attest): the last
	// one a verifier accepted.
	Counter uint64

	State State
	// Reason is why the instance was last suspended or revoked.
	Reason string

	CreatedAt  time.Time
	LastSeenAt time.Time

	// WalletAttestations and KeyAttestations count the attestations
	// issued for the instance.
	WalletAttestations uint64
	KeyAttestations    uint64

	// IndexPeriodStart is the start, in seconds since the Unix epoch, of
	// the status list period IndicesInPeriod counts in, and
	// IndicesInPeriod how many status list indices the instance's
	// instance keys took in it, which Config.MaxInstanceKeysPerPeriod
	// bounds. Both are zero for an instance whose keys have taken none
	// since the provider counted them (v0.75.3 and before).
	IndexPeriodStart int64
	IndicesInPeriod  int

	// Revision is the store's version of the record: Create stores 1,
	// and each Update one more. Update compares it to detect a
	// concurrent change.
	Revision uint64
}

// clone returns a copy of in sharing no memory with it.
func (in Instance) clone() Instance {
	in.Key = slices.Clone(in.Key)
	in.Credential = slices.Clone(in.Credential)
	return in
}

// InstanceStore keeps registered instances. A production store is
// durable and shared by every process serving the provider, as the
// github.com/idfoundry/oid4vcgo/sqlstore module's
// DB.WalletProviderInstances is.
type InstanceStore interface {
	// Get returns the instance with id, or an error wrapping ErrNotFound.
	Get(ctx context.Context, id string) (Instance, error)

	// Create stores in with Revision 1 (whatever in.Revision is), or
	// returns an error wrapping ErrExists if an instance with its ID,
	// with its KeyThumbprint, or with its CredentialID when that isn't
	// empty, is stored: one registration key, and one App Attest key,
	// registers one instance. The check and the store are one atomic
	// step, as a UNIQUE constraint on each column makes them (with
	// CredentialID's column NULL when it's empty).
	Create(ctx context.Context, in Instance) error

	// Update replaces the stored instance with in's ID by in, with
	// Revision in.Revision+1, if the stored one's Revision is
	// in.Revision — one atomic compare-and-swap, as an UPDATE ... WHERE
	// revision = ? is. It returns an error wrapping ErrConflict, and
	// changes nothing, if the stored Revision differs, and ErrNotFound
	// if no instance has the ID. The provider never changes an
	// instance's KeyThumbprint or CredentialID.
	Update(ctx context.Context, in Instance) error

	// List returns up to limit instances whose IDs sort after after
	// (every one when after is empty), in ascending ID order: a page of
	// a walk over every instance, for bulk actions. limit is positive.
	List(ctx context.Context, after string, limit int) ([]Instance, error)
}

// MemoryInstanceStore is an InstanceStore held in memory, safe for
// concurrent use; its zero value is ready to use. It isn't durable: a
// restart forgets every instance. For tests and demos.
type MemoryInstanceStore struct {
	mu        sync.Mutex
	instances map[string]Instance
}

var _ InstanceStore = (*MemoryInstanceStore)(nil)

// Get implements InstanceStore.
func (s *MemoryInstanceStore) Get(ctx context.Context, id string) (Instance, error) {
	if err := ctx.Err(); err != nil {
		return Instance{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.instances[id]
	if !ok {
		return Instance{}, ErrNotFound
	}
	return in.clone(), nil
}

// Create implements InstanceStore.
func (s *MemoryInstanceStore) Create(ctx context.Context, in Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.instances[in.ID]; ok {
		return ErrExists
	}
	for _, stored := range s.instances {
		if stored.KeyThumbprint == in.KeyThumbprint || in.CredentialID != "" && stored.CredentialID == in.CredentialID {
			return ErrExists
		}
	}
	if s.instances == nil {
		s.instances = make(map[string]Instance)
	}
	in = in.clone()
	in.Revision = 1
	s.instances[in.ID] = in
	return nil
}

// Update implements InstanceStore.
func (s *MemoryInstanceStore) Update(ctx context.Context, in Instance) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.instances[in.ID]
	switch {
	case !ok:
		return ErrNotFound
	case stored.Revision != in.Revision:
		return ErrConflict
	}
	in = in.clone()
	in.Revision++
	s.instances[in.ID] = in
	return nil
}

// List implements InstanceStore.
func (s *MemoryInstanceStore) List(ctx context.Context, after string, limit int) ([]Instance, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0, len(s.instances))
	for id := range s.instances {
		if id > after {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:max(limit, 0)]
	}
	out := make([]Instance, len(ids))
	for i, id := range ids {
		out[i] = s.instances[id].clone()
	}
	return out, nil
}
