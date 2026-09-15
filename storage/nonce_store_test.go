package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
)

func TestNonceStore_IssueThenConsume(t *testing.T) {
	s := storage.NewNonceStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)

	if err := s.Issue(ctx, issuer.NonceIssuance{Nonce: "nonce-1", ExpiresAt: expires}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	record, err := s.Consume(ctx, issuer.NonceConsumption{Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !record.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, expires)
	}
}

func TestNonceStore_ConsumeIsSingleUse(t *testing.T) {
	s := storage.NewNonceStore()
	ctx := context.Background()
	if err := s.Issue(ctx, issuer.NonceIssuance{Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(ctx, issuer.NonceConsumption{Nonce: "nonce-1"}); err != nil {
		t.Fatalf("Consume (first): %v", err)
	}
	if _, err := s.Consume(ctx, issuer.NonceConsumption{Nonce: "nonce-1"}); err == nil {
		t.Fatalf("Consume (second) = nil error, want error")
	}
}

func TestNonceStore_ConsumeRejectsUnknownNonce(t *testing.T) {
	s := storage.NewNonceStore()
	if _, err := s.Consume(context.Background(), issuer.NonceConsumption{Nonce: "never-issued"}); err == nil {
		t.Fatalf("Consume = nil error, want error")
	}
}
