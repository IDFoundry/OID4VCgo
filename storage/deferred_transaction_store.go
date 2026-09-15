package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcigo/issuer"
)

// DeferredTransactionStore is an in-memory issuer.DeferredTransactionStore.
// See the package doc comment for why this is development/testing only.
//
// issuer.DeferredTransactionStore only defines Get/Invalidate — by
// design, issuer never creates or resolves a Deferred Issuance
// transaction itself (see issuer.DeferredTransactionRecord's own doc
// comment). Put is this store's own extra method, for whatever stands
// in here for that business process: call it once to create a
// transaction (ordinarily DeferredTransactionPending), and again,
// later, to move it to DeferredTransactionIssued or
// DeferredTransactionDenied.
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
	record.Credentials = cloneIssuedCredentials(record.Credentials)
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
	record.Credentials = cloneIssuedCredentials(record.Credentials)
	return record, nil
}

// Invalidate implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Invalidate(_ context.Context, transactionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated[transactionID] = true
	return nil
}
