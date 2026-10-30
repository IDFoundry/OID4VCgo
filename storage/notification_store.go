package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// NotificationStore is an in-memory issuer.NotificationStore. See the
// package doc comment for why this is development/testing only.
// Records past their ExpiresAt are dropped as the store grows.
type NotificationStore struct {
	mu      sync.Mutex
	records map[string]issuer.NotificationRecord
	prune   pruner
}

// NewNotificationStore builds an empty NotificationStore.
func NewNotificationStore() *NotificationStore {
	return &NotificationStore{records: make(map[string]issuer.NotificationRecord)}
}

// Issue implements issuer.NotificationStore.
func (s *NotificationStore) Issue(_ context.Context, notificationID string, record issuer.NotificationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now, ok := s.prune.due(len(s.records)); ok {
		pruneMap(s.records, now, func(r issuer.NotificationRecord) time.Time { return r.ExpiresAt })
		s.prune.pruned(len(s.records))
	}
	s.records[notificationID] = record
	return nil
}

// Get implements issuer.NotificationStore.
func (s *NotificationStore) Get(_ context.Context, notificationID string) (issuer.NotificationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[notificationID]
	if !ok {
		return issuer.NotificationRecord{}, fmt.Errorf("storage: %w", issuer.ErrNotificationIDUnknown)
	}
	return record, nil
}
