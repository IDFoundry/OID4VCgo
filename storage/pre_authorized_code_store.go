package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// PreAuthorizedCodeStore is an in-memory issuer.PreAuthorizedCodeStore.
// See the package doc comment for why this is development/testing
// only.
type PreAuthorizedCodeStore struct {
	mu     sync.Mutex
	issued map[string]issuer.PreAuthorizedCodeRecord
}

// NewPreAuthorizedCodeStore builds an empty PreAuthorizedCodeStore.
func NewPreAuthorizedCodeStore() *PreAuthorizedCodeStore {
	return &PreAuthorizedCodeStore{issued: make(map[string]issuer.PreAuthorizedCodeRecord)}
}

// Issue implements issuer.PreAuthorizedCodeStore.
func (s *PreAuthorizedCodeStore) Issue(_ context.Context, code string, record issuer.PreAuthorizedCodeRecord) error {
	record.Scopes = cloneStrings(record.Scopes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[code] = record
	return nil
}

// Consume implements issuer.PreAuthorizedCodeStore. Deleting the map
// entry on every call — whether or not it was present — is what makes
// this single-use: a second Consume of the same code always finds
// nothing, the same shape NonceStore.Consume already establishes.
func (s *PreAuthorizedCodeStore) Consume(_ context.Context, code string) (issuer.PreAuthorizedCodeRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[code]
	delete(s.issued, code)
	if !ok {
		return issuer.PreAuthorizedCodeRecord{}, fmt.Errorf("storage: unknown or already-consumed pre-authorized_code")
	}
	record.Scopes = cloneStrings(record.Scopes)
	return record, nil
}
