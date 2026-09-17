package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/storage"
)

func TestDPoPNonceStore_IssueThenConsume(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)

	if err := s.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "nonce-1", ExpiresAt: expires}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	record, err := s.Consume(ctx, issuer.DPoPNonceConsumption{Nonce: "nonce-1"})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !record.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, expires)
	}
}

func TestDPoPNonceStore_ConsumeIsSingleUse(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	ctx := context.Background()
	if err := s.Issue(ctx, issuer.DPoPNonceIssuance{Nonce: "nonce-1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(ctx, issuer.DPoPNonceConsumption{Nonce: "nonce-1"}); err != nil {
		t.Fatalf("Consume (first): %v", err)
	}
	if _, err := s.Consume(ctx, issuer.DPoPNonceConsumption{Nonce: "nonce-1"}); err == nil {
		t.Fatalf("Consume (second) = nil error, want error")
	}
}

func TestDPoPNonceStore_ConsumeRejectsUnknownNonce(t *testing.T) {
	s := storage.NewDPoPNonceStore()
	if _, err := s.Consume(context.Background(), issuer.DPoPNonceConsumption{Nonce: "never-issued"}); err == nil {
		t.Fatalf("Consume = nil error, want error")
	}
}
