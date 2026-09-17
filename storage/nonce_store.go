package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// NonceStore is an in-memory issuer.NonceStore. See the package doc
// comment for why this is development/testing only.
type NonceStore struct {
	mu     sync.Mutex
	issued map[string]issuer.NonceRecord
}

// NewNonceStore builds an empty NonceStore.
func NewNonceStore() *NonceStore {
	return &NonceStore{issued: make(map[string]issuer.NonceRecord)}
}

// Issue implements issuer.NonceStore.
func (s *NonceStore) Issue(_ context.Context, issuance issuer.NonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[issuance.Nonce] = issuer.NonceRecord{ExpiresAt: issuance.ExpiresAt}
	return nil
}

// Consume implements issuer.NonceStore. Deleting the map entry on
// every call — whether or not it was present — is what makes this
// single-use: a second Consume of the same nonce always finds nothing.
func (s *NonceStore) Consume(_ context.Context, consumption issuer.NonceConsumption) (issuer.NonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[consumption.Nonce]
	delete(s.issued, consumption.Nonce)
	if !ok {
		return issuer.NonceRecord{}, fmt.Errorf("storage: unknown or already-consumed nonce")
	}
	return record, nil
}
