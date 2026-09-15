// Package testverify holds small shared assertion helpers for
// verifier.VerifyResponse tests across packages (verifier, wallet) —
// never for production use. A regular (not _test.go) package for the
// same reason internal/testcert/internal/testmdoc are: Go doesn't let
// a _test.go file's own symbols be imported from another package's
// tests.
package testverify

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/verifier"
)

// RequireOneCredential asserts a successful VerifyResponse call
// (err nil) returned exactly one VerifiedCredential with
// CredentialQueryID wantID, and returns it.
func RequireOneCredential(t *testing.T, result verifier.VerifyResponseResult, err error, wantID string) verifier.VerifiedCredential {
	t.Helper()
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}
	if result.Credentials[0].CredentialQueryID != wantID {
		t.Errorf("CredentialQueryID = %q, want %q", result.Credentials[0].CredentialQueryID, wantID)
	}
	return result.Credentials[0]
}
