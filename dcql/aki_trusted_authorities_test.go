package dcql_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// TestAKITrustedAuthorities_MatchesTheCAsLeaves checks the query built
// from a CA matches a leaf that CA issued, under the same checker the
// Wallet and Verifier use, and not a leaf from another CA.
func TestAKITrustedAuthorities_MatchesTheCAsLeaves(t *testing.T) {
	ca, caKey := testcert.CA(t, "trusted CA")
	leaf, _ := testcert.Leaf(t, "issuer", ca, caKey)
	otherCA, otherKey := testcert.CA(t, "other CA")
	otherLeaf, _ := testcert.Leaf(t, "other issuer", otherCA, otherKey)

	query, err := dcql.AKITrustedAuthorities(ca)
	if err != nil {
		t.Fatalf("AKITrustedAuthorities: %v", err)
	}
	if query.Type != dcql.TrustedAuthorityAKI || len(query.Values) != 1 {
		t.Fatalf("query = %+v", query)
	}
	if err := query.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	checker := dcql.AKITrustedAuthoritiesChecker{}
	queries := []dcql.TrustedAuthoritiesQuery{query}
	if err := checker.CheckTrustedAuthorities(context.Background(), queries, [][]byte{leaf.Raw}); err != nil {
		t.Errorf("the CA's own leaf: %v", err)
	}
	if err := checker.CheckTrustedAuthorities(context.Background(), queries, [][]byte{otherLeaf.Raw}); err == nil {
		t.Error("a leaf from another CA matched")
	}

	both, err := dcql.AKITrustedAuthorities(ca, otherCA)
	if err != nil || len(both.Values) != 2 {
		t.Fatalf("two CAs: %+v, %v", both, err)
	}
}

func TestAKITrustedAuthorities_Rejects(t *testing.T) {
	if _, err := dcql.AKITrustedAuthorities(); err == nil {
		t.Error("no CAs accepted")
	}
	if _, err := dcql.AKITrustedAuthorities(nil); err == nil {
		t.Error("a nil CA accepted")
	}
	if _, err := dcql.AKITrustedAuthorities(&x509.Certificate{}); err == nil {
		t.Error("a CA without a Subject Key Identifier accepted")
	}
}
