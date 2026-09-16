// Package testverify holds small shared assertion helpers and query
// fixtures for verifier.VerifyResponse tests across packages
// (verifier, wallet) — never for production use. A regular (not
// _test.go) package for the same reason internal/testcert/
// internal/testmdoc are: Go doesn't let a _test.go file's own symbols
// be imported from another package's tests.
package testverify

import (
	"testing"

	"github.com/idfoundry/oid4vcigo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcigo/dcql"
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

// ClaimSetOptionsQuery returns a dcql.Query with one CredentialQuery
// (ID "identity_credential", format "dc+sd-jwt", VCT vct) whose
// claim_sets has two options: an unsatisfiable first option
// ("no_such_claim") and a satisfiable second option ("given_name") —
// shared by wallet.TestMatchDCQLQueryAcceptsSatisfiableClaimSetOption
// and verifier.TestVerifyResponseAcceptsSatisfiableClaimSetOption to
// exercise §6.4.1's "first satisfiable option wins" preference order
// identically on both sides.
func ClaimSetOptionsQuery(t *testing.T, vct string) dcql.Query {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{vct}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{
			{ID: "no_such_claim", Path: dcql.Path{dcql.PathKey("no_such_claim")}},
			{ID: "given_name", Path: dcql.Path{dcql.PathKey("given_name")}},
		},
		ClaimSets: [][]string{{"no_such_claim"}, {"given_name"}},
	}}}
}
