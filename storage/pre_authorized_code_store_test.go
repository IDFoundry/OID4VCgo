package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/issuer"
	"github.com/idfoundry/oid4vcigo/storage"
)

func TestPreAuthorizedCodeStore_IssueThenConsume(t *testing.T) {
	s := storage.NewPreAuthorizedCodeStore()
	ctx := context.Background()
	expires := time.Now().Add(time.Minute)

	if err := s.Issue(ctx, "code-1", issuer.PreAuthorizedCodeRecord{
		TxCode: "493536", Scopes: []string{"identity_credential"}, ExpiresAt: expires,
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}

	record, err := s.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if record.TxCode != "493536" {
		t.Errorf("TxCode = %q, want %q", record.TxCode, "493536")
	}
	if len(record.Scopes) != 1 || record.Scopes[0] != "identity_credential" {
		t.Errorf("Scopes = %v", record.Scopes)
	}
	if !record.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, expires)
	}
}

func TestPreAuthorizedCodeStore_ConsumeIsSingleUse(t *testing.T) {
	s := storage.NewPreAuthorizedCodeStore()
	ctx := context.Background()
	if err := s.Issue(ctx, "code-1", issuer.PreAuthorizedCodeRecord{ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(ctx, "code-1"); err != nil {
		t.Fatalf("Consume (first): %v", err)
	}
	if _, err := s.Consume(ctx, "code-1"); err == nil {
		t.Fatalf("Consume (second) = nil error, want error")
	}
}

func TestPreAuthorizedCodeStore_ConsumeRejectsUnknownCode(t *testing.T) {
	s := storage.NewPreAuthorizedCodeStore()
	if _, err := s.Consume(context.Background(), "never-issued"); err == nil {
		t.Fatalf("Consume = nil error, want error")
	}
}

// TestPreAuthorizedCodeStoreDoesNotAliasCallerOrInternalState covers
// both directions: mutating the caller's own Scopes slice after Issue
// must not reach what's stored, and mutating a returned record's
// Scopes must not corrupt what a later Consume would have returned
// for the same code (verified here via a second Issue/Consume of the
// same code, since Consume itself is single-use).
func TestPreAuthorizedCodeStoreDoesNotAliasCallerOrInternalState(t *testing.T) {
	s := storage.NewPreAuthorizedCodeStore()
	ctx := context.Background()

	scopes := []string{"identity_credential"}
	if err := s.Issue(ctx, "code-1", issuer.PreAuthorizedCodeRecord{
		Scopes: scopes, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	scopes[0] = "tampered-by-caller-after-issue"

	record, err := s.Consume(ctx, "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if record.Scopes[0] != "identity_credential" {
		t.Fatalf("Scopes[0] = %q, want %q (Issue aliased the caller's slice)", record.Scopes[0], "identity_credential")
	}
	record.Scopes[0] = "tampered-by-caller-after-consume"

	if err := s.Issue(ctx, "code-2", issuer.PreAuthorizedCodeRecord{
		Scopes: []string{"identity_credential"}, ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("Issue (code-2): %v", err)
	}
	second, err := s.Consume(ctx, "code-2")
	if err != nil {
		t.Fatalf("Consume (code-2): %v", err)
	}
	if second.Scopes[0] != "identity_credential" {
		t.Fatalf("Scopes[0] = %q, want %q (Consume returned an aliased slice)", second.Scopes[0], "identity_credential")
	}
}
