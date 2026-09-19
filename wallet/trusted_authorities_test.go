package wallet_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// trustedAuthoritiesQuery is testPresentationQuery with a
// TrustedAuthorities restriction of type aki added — everything else
// identical.
func trustedAuthoritiesQuery(t *testing.T, aki string) dcql.Query {
	t.Helper()
	query := testPresentationQuery(t)
	query.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthoritiesQuery{
		{Type: dcql.TrustedAuthorityAKI, Values: []string{aki}},
	}
	return query
}

func TestMatchDCQLQuery_RejectsMissingTrustedAuthoritiesDependency(t *testing.T) {
	fixture := newHeldSDJWTVC(t)
	query := trustedAuthoritiesQuery(t, "anything")
	if _, err := wallet.MatchDCQLQuery(context.Background(), query, []wallet.HeldCredential{fixture.held}, nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error (trusted_authorities dependency missing)")
	}
}

func TestMatchDCQLQuery_ChecksTrustedAuthorities_IncludesTrustedCandidate(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	fixture := newHeldSDJWTVCWithOpts(t, leafKey, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, map[string]any{"given_name": "Alice"})
	query := trustedAuthoritiesQuery(t, aki)

	matches, err := wallet.MatchDCQLQuery(context.Background(), query, []wallet.HeldCredential{fixture.held}, dcql.AKITrustedAuthoritiesChecker{})
	if err != nil {
		t.Fatalf("MatchDCQLQuery: %v", err)
	}
	if len(matches["identity_credential"]) != 1 {
		t.Fatalf("matches = %+v, want exactly one identity_credential match", matches)
	}
}

func TestMatchDCQLQuery_ChecksTrustedAuthorities_ExcludesUntrustedCandidate(t *testing.T) {
	ca, caKey := testcert.CA(t, "test-ca")
	leaf, leafKey := testcert.Leaf(t, "test-leaf", ca, caKey)

	fixture := newHeldSDJWTVCWithOpts(t, leafKey, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, map[string]any{"given_name": "Alice"})
	query := trustedAuthoritiesQuery(t, "not-the-right-aki")

	if _, err := wallet.MatchDCQLQuery(context.Background(), query, []wallet.HeldCredential{fixture.held}, dcql.AKITrustedAuthoritiesChecker{}); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error (candidate's aki does not match)")
	}
}

// TestMatchDCQLQueryMdoc_RejectsMissingTrustedAuthoritiesDependency
// mirrors TestMatchDCQLQuery_RejectsMissingTrustedAuthoritiesDependency
// for the "mso_mdoc" match path (matchAllMdocQuery's own separate
// TrustedAuthorities check) — same fail-closed gate, different format.
func TestMatchDCQLQueryMdoc_RejectsMissingTrustedAuthoritiesDependency(t *testing.T) {
	f := testmdoc.Issue(t)
	held := heldMdoc(t, f)
	query := testmdoc.Query(t)
	query.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthoritiesQuery{
		{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}},
	}

	if _, err := wallet.MatchDCQLQuery(context.Background(), query, []wallet.HeldCredential{held}, nil); err == nil {
		t.Fatalf("MatchDCQLQuery = nil error, want error (trusted_authorities dependency missing)")
	}
}
