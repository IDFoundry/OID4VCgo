// Package testverify holds small shared assertion helpers and query
// fixtures for verifier.VerifyResponse tests across packages
// (verifier, wallet) — never for production use. A regular (not
// _test.go) package for the same reason internal/testcert/
// internal/testmdoc are: Go doesn't let a _test.go file's own symbols
// be imported from another package's tests.
package testverify

import (
	"encoding/json"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
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

// MustSDJWTVCMeta builds a "dc+sd-jwt" Meta value constrained to vct,
// failing the test on error — the one-liner every "dc+sd-jwt" query
// fixture across verifier/wallet tests needs.
func MustSDJWTVCMeta(t *testing.T, vct string) json.RawMessage {
	t.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{vct}})
	if err != nil {
		t.Fatalf("NewSDJWTVCMeta: %v", err)
	}
	return meta
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
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "identity_credential", Format: sdjwtvc.CredentialFormat, Meta: MustSDJWTVCMeta(t, vct),
		Claims: []dcql.ClaimsQuery{
			{ID: "no_such_claim", Path: dcql.Path{dcql.PathKey("no_such_claim")}},
			{ID: "given_name", Path: dcql.Path{dcql.PathKey("given_name")}},
		},
		ClaimSets: [][]string{{"no_such_claim"}, {"given_name"}},
	}}}
}
