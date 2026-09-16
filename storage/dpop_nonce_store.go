package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcigo/issuer"
)

// DPoPNonceStore is an in-memory issuer.DPoPNonceStore. See the
// package doc comment for why this is development/testing only.
type DPoPNonceStore struct {
	mu     sync.Mutex
	issued map[string]issuer.DPoPNonceRecord
}

// NewDPoPNonceStore builds an empty DPoPNonceStore.
func NewDPoPNonceStore() *DPoPNonceStore {
	return &DPoPNonceStore{issued: make(map[string]issuer.DPoPNonceRecord)}
}

// Issue implements issuer.DPoPNonceStore.
func (s *DPoPNonceStore) Issue(_ context.Context, issuance issuer.DPoPNonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[issuance.Nonce] = issuer.DPoPNonceRecord{ExpiresAt: issuance.ExpiresAt}
	return nil
}

// Consume implements issuer.DPoPNonceStore. Deleting the map entry on
// every call — whether or not it was present — is what makes this
// single-use: a second Consume of the same nonce always finds nothing.
func (s *DPoPNonceStore) Consume(_ context.Context, consumption issuer.DPoPNonceConsumption) (issuer.DPoPNonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[consumption.Nonce]
	delete(s.issued, consumption.Nonce)
	if !ok {
		return issuer.DPoPNonceRecord{}, fmt.Errorf("storage: unknown or already-consumed dpop nonce")
	}
	return record, nil
}
