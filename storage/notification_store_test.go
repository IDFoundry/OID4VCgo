package storage_test

import (
	"context"
	"testing"

	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
)

func TestNotificationStore_IssueThenGet(t *testing.T) {
	s := storage.NewNotificationStore()
	ctx := context.Background()

	if err := s.Issue(ctx, "notif-1", issuer.NotificationRecord{ClientID: "client-a"}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	record, err := s.Get(ctx, "notif-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if record.ClientID != "client-a" {
		t.Errorf("ClientID = %q, want %q", record.ClientID, "client-a")
	}
}

func TestNotificationStore_GetIsRepeatable(t *testing.T) {
	s := storage.NewNotificationStore()
	ctx := context.Background()
	if err := s.Issue(ctx, "notif-1", issuer.NotificationRecord{}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Get(ctx, "notif-1"); err != nil {
		t.Fatalf("Get (first): %v", err)
	}
	if _, err := s.Get(ctx, "notif-1"); err != nil {
		t.Fatalf("Get (second): %v", err)
	}
}

func TestNotificationStore_GetRejectsUnknownID(t *testing.T) {
	s := storage.NewNotificationStore()
	if _, err := s.Get(context.Background(), "no-such-id"); err == nil {
		t.Fatalf("Get = nil error, want error")
	}
}
