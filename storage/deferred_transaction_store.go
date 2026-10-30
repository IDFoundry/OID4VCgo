package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// DeferredTransactionStore is an in-memory issuer.DeferredTransactionStore.
// See the package doc comment for why this is development/testing only.
// One lock serializes every Update. Put, beyond the interface, creates
// or replaces a record directly, for a test or a business process that
// manages transactions itself. Transactions past their ExpiresAt,
// which the issuer answers as unknown, are dropped as the store grows.
type DeferredTransactionStore struct {
	mu          sync.Mutex
	records     map[string]issuer.DeferredTransactionRecord
	invalidated map[string]bool
	prune       pruner
}

// NewDeferredTransactionStore builds an empty DeferredTransactionStore.
func NewDeferredTransactionStore() *DeferredTransactionStore {
	return &DeferredTransactionStore{
		records:     make(map[string]issuer.DeferredTransactionRecord),
		invalidated: make(map[string]bool),
	}
}

// Put creates or replaces the transaction identified by transactionID.
// It also un-invalidates transactionID, so a caller can reuse an
// invalidated transaction_id for a fresh transaction, though in
// practice each transaction_id should be its own unique, unguessable
// value.
func (s *DeferredTransactionStore) Put(_ context.Context, transactionID string, record issuer.DeferredTransactionRecord) error {
	record = cloneDeferredRecord(record)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpired()
	s.records[transactionID] = record
	delete(s.invalidated, transactionID)
	return nil
}

// pruneExpired drops expired transactions, invalidated or not, once
// the store has grown enough to look. s.mu must be held.
func (s *DeferredTransactionStore) pruneExpired() {
	now, ok := s.prune.due(len(s.records))
	if !ok {
		return
	}
	pruneMap(s.records, now, func(r issuer.DeferredTransactionRecord) time.Time { return r.ExpiresAt })
	for id := range s.invalidated {
		if _, kept := s.records[id]; !kept {
			delete(s.invalidated, id)
		}
	}
	s.prune.pruned(len(s.records))
}

// Get implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Get(_ context.Context, transactionID string) (issuer.DeferredTransactionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalidated[transactionID] {
		return issuer.DeferredTransactionRecord{}, fmt.Errorf("storage: %w", issuer.ErrDeferredTransactionUnknown)
	}
	record, ok := s.records[transactionID]
	if !ok {
		return issuer.DeferredTransactionRecord{}, fmt.Errorf("storage: %w", issuer.ErrDeferredTransactionUnknown)
	}
	return cloneDeferredRecord(record), nil
}

// Create implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Create(_ context.Context, transactionID string, record issuer.DeferredTransactionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if transactionID == "" {
		return fmt.Errorf("storage: transaction_id is required")
	}
	s.pruneExpired()
	if _, used := s.records[transactionID]; used || s.invalidated[transactionID] {
		return fmt.Errorf("storage: transaction_id is already in use")
	}
	s.records[transactionID] = cloneDeferredRecord(record)
	return nil
}

// Update implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Update(_ context.Context, transactionID string, fn func(*issuer.DeferredTransactionRecord) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.records[transactionID]
	if !ok || s.invalidated[transactionID] {
		return fmt.Errorf("storage: %w", issuer.ErrDeferredTransactionUnknown)
	}
	record := cloneDeferredRecord(stored)
	if err := fn(&record); err != nil {
		return err
	}
	s.records[transactionID] = cloneDeferredRecord(record)
	return nil
}

// cloneDeferredRecord returns a copy of r sharing no slice with it —
// see cloneStrings' own doc comment.
func cloneDeferredRecord(r issuer.DeferredTransactionRecord) issuer.DeferredTransactionRecord {
	r.Credentials = cloneIssuedCredentials(r.Credentials)
	if r.BindingKeys != nil {
		keys := make([]json.RawMessage, len(r.BindingKeys))
		for i, k := range r.BindingKeys {
			keys[i] = append(json.RawMessage(nil), k...)
		}
		r.BindingKeys = keys
	}
	r.KeyAttestations = cloneStrings(r.KeyAttestations)
	return r
}

// Invalidate implements issuer.DeferredTransactionStore. It drops the
// record's Credentials, which the Wallet now holds; the rest is kept
// so the transaction_id stays used.
func (s *DeferredTransactionStore) Invalidate(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[transactionID]
	if !ok || s.invalidated[transactionID] {
		return fmt.Errorf("storage: %w", issuer.ErrDeferredTransactionUnknown)
	}
	record.Credentials = nil
	s.records[transactionID] = record
	s.invalidated[transactionID] = true
	return nil
}
