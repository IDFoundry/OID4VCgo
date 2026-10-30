package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// NonceStore is an in-memory issuer.NonceStore. See the package doc
// comment for why this is development/testing only.
type NonceStore struct {
	mu     sync.Mutex
	issued map[string]issuer.NonceRecord
	prune  pruner
}

// NewNonceStore builds an empty NonceStore.
func NewNonceStore() *NonceStore {
	return &NonceStore{issued: make(map[string]issuer.NonceRecord)}
}

// Issue implements issuer.NonceStore.
func (s *NonceStore) Issue(_ context.Context, issuance issuer.NonceIssuance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, ok := s.prune.due(len(s.issued)); ok {
		pruneMap(s.issued, now, func(r issuer.NonceRecord) time.Time { return r.ExpiresAt })
		s.prune.pruned(len(s.issued))
	}
	s.issued[issuance.Nonce] = issuer.NonceRecord{Owner: issuance.Owner, ExpiresAt: issuance.ExpiresAt}
	return nil
}

// Consume implements issuer.NonceStore. Deleting the map entry it
// returns is what makes this single-use: a second Consume of the same
// nonce finds nothing. A nonce issued to another Owner is left in place.
func (s *NonceStore) Consume(_ context.Context, consumption issuer.NonceConsumption) (issuer.NonceRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[consumption.Nonce]
	if !ok || record.Owner != consumption.Owner {
		return issuer.NonceRecord{}, fmt.Errorf("storage: %w", issuer.ErrNonceUnknown)
	}
	delete(s.issued, consumption.Nonce)
	return record, nil
}
