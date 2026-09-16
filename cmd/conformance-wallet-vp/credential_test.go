package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
	"github.com/idfoundry/oid4vcigo/internal/jose"
)

// TestIssueFixtureCredential_SetsExp reuses setupWalletUnderTest (the
// same real issueFixtureCredential call path integration_test.go's
// own full round-trip test exercises) rather than duplicating its own
// key/CA/cert setup, and just checks the one thing that test doesn't:
// the issued credential's own "exp" claim, day-rounded per
// conformancecert.CredentialExp's own doc comment.
func TestIssueFixtureCredential_SetsExp(t *testing.T) {
	before := time.Now()
	wallet, _ := setupWalletUnderTest(t)

	issuerJWT, _, _ := strings.Cut(wallet.cred.Credential, "~")
	_, rawPayload, err := jose.DecodeUnverified(issuerJWT)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var payload struct {
		Exp *int64 `json:"exp"`
	}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Exp == nil {
		t.Fatal("issued credential has no exp claim")
	}
	want := conformancecert.CredentialExp(before, fixtureCredentialLifetime)
	if *payload.Exp != want {
		t.Errorf("exp = %d, want %d (day-rounded issuance + fixtureCredentialLifetime)", *payload.Exp, want)
	}
}
