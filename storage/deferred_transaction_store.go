package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// DeferredTransactionStore is an in-memory issuer.DeferredTransactionStore.
// See the package doc comment for why this is development/testing only.
// One lock serializes every Update. Put, beyond the interface, creates
// or replaces a record directly, for a test or a business process that
// manages transactions itself.
type DeferredTransactionStore struct {
	mu          sync.Mutex
	records     map[string]issuer.DeferredTransactionRecord
	invalidated map[string]bool
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
	s.records[transactionID] = record
	delete(s.invalidated, transactionID)
	return nil
}

// Get implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Get(_ context.Context, transactionID string) (issuer.DeferredTransactionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.invalidated[transactionID] {
		return issuer.DeferredTransactionRecord{}, fmt.Errorf("storage: unknown or invalidated transaction_id")
	}
	record, ok := s.records[transactionID]
	if !ok {
		return issuer.DeferredTransactionRecord{}, fmt.Errorf("storage: unknown or invalidated transaction_id")
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
		return fmt.Errorf("storage: unknown or invalidated transaction_id")
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
	return r
}

// Invalidate implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Invalidate(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.records[transactionID]; !ok || s.invalidated[transactionID] {
		return fmt.Errorf("storage: unknown or already-invalidated transaction_id")
	}
	s.invalidated[transactionID] = true
	return nil
}
