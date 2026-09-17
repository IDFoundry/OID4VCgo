package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/storage"
)

func TestDPoPReplayChecker_UseOnceAllowsFirstUse(t *testing.T) {
	s := storage.NewDPoPReplayChecker()
	if err := s.UseOnce(context.Background(), "jti-1", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("UseOnce: %v", err)
	}
}

func TestDPoPReplayChecker_UseOnceRejectsRepeat(t *testing.T) {
	s := storage.NewDPoPReplayChecker()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)
	if err := s.UseOnce(ctx, "jti-1", expires); err != nil {
		t.Fatalf("UseOnce (first): %v", err)
	}
	if err := s.UseOnce(ctx, "jti-1", expires); err == nil {
		t.Fatalf("UseOnce (second) = nil error, want error")
	}
}

func TestDPoPReplayChecker_DistinctJTIsIndependent(t *testing.T) {
	s := storage.NewDPoPReplayChecker()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)
	if err := s.UseOnce(ctx, "jti-1", expires); err != nil {
		t.Fatalf("UseOnce jti-1: %v", err)
	}
	if err := s.UseOnce(ctx, "jti-2", expires); err != nil {
		t.Fatalf("UseOnce jti-2: %v", err)
	}
}
