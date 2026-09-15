package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcigo/issuer"
)

// NotificationStore is an in-memory issuer.NotificationStore. See the
// package doc comment for why this is development/testing only.
type NotificationStore struct {
	mu      sync.Mutex
	records map[string]issuer.NotificationRecord
}

// NewNotificationStore builds an empty NotificationStore.
func NewNotificationStore() *NotificationStore {
	return &NotificationStore{records: make(map[string]issuer.NotificationRecord)}
}

// Issue implements issuer.NotificationStore.
func (s *NotificationStore) Issue(_ context.Context, notificationID string, record issuer.NotificationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[notificationID] = record
	return nil
}

// Get implements issuer.NotificationStore.
func (s *NotificationStore) Get(_ context.Context, notificationID string) (issuer.NotificationRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.records[notificationID]
	if !ok {
		return issuer.NotificationRecord{}, fmt.Errorf("storage: unknown notification_id")
	}
	return record, nil
}
