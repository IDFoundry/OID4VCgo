package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcigo/issuer"
)

// CredentialOfferStore is an in-memory issuer.CredentialOfferStore. See
// the package doc comment for why this is development/testing only.
type CredentialOfferStore struct {
	mu      sync.Mutex
	records map[string]issuer.CredentialOfferRecord
}

// NewCredentialOfferStore builds an empty CredentialOfferStore.
func NewCredentialOfferStore() *CredentialOfferStore {
	return &CredentialOfferStore{records: make(map[string]issuer.CredentialOfferRecord)}
}

// Store implements issuer.CredentialOfferStore.
func (s *CredentialOfferStore) Store(_ context.Context, record issuer.CredentialOfferRecord) error {
	record.Offer = cloneCredentialOffer(record.Offer)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[record.Reference] = record
	return nil
}

// Get implements issuer.CredentialOfferStore.
func (s *CredentialOfferStore) Get(_ context.Context, reference string) (issuer.CredentialOfferRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[reference]
	if !ok {
		return issuer.CredentialOfferRecord{}, fmt.Errorf("storage: unknown credential offer reference")
	}
	record.Offer = cloneCredentialOffer(record.Offer)
	return record, nil
}
