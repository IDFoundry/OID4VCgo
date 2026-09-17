package storage_test

import (
	"context"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

func TestDeferredTransactionStore_PutThenGet(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	ctx := context.Background()

	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{
		ClientID: "client-a", Status: issuer.DeferredTransactionPending,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, "txn-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != issuer.DeferredTransactionPending || got.ClientID != "client-a" {
		t.Errorf("record = %+v", got)
	}
}

func TestDeferredTransactionStore_PutResolvesTransaction(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	ctx := context.Background()

	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending}); err != nil {
		t.Fatalf("Put (pending): %v", err)
	}
	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{
		Status:      issuer.DeferredTransactionIssued,
		Credentials: []oid4vci.IssuedCredential{{Credential: "signed-credential"}},
	}); err != nil {
		t.Fatalf("Put (issued): %v", err)
	}

	got, err := s.Get(ctx, "txn-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != issuer.DeferredTransactionIssued || len(got.Credentials) != 1 || got.Credentials[0].Credential != "signed-credential" {
		t.Errorf("record = %+v", got)
	}
}

func TestDeferredTransactionStore_GetRejectsUnknownTransaction(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	if _, err := s.Get(context.Background(), "no-such-transaction"); err == nil {
		t.Fatalf("Get = nil error, want error")
	}
}

func TestDeferredTransactionStore_InvalidateRetiresTransaction(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	ctx := context.Background()
	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionIssued}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Invalidate(ctx, "txn-1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if _, err := s.Get(ctx, "txn-1"); err == nil {
		t.Fatalf("Get after Invalidate = nil error, want error")
	}
}

func TestDeferredTransactionStore_PutAfterInvalidateRevives(t *testing.T) {
	s := storage.NewDeferredTransactionStore()
	ctx := context.Background()
	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionIssued}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Invalidate(ctx, "txn-1"); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if err := s.Put(ctx, "txn-1", issuer.DeferredTransactionRecord{Status: issuer.DeferredTransactionPending}); err != nil {
		t.Fatalf("Put (after invalidate): %v", err)
	}
	got, err := s.Get(ctx, "txn-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != issuer.DeferredTransactionPending {
		t.Errorf("Status = %v, want Pending", got.Status)
	}
}
