package dcql_test

import (
	"context"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// BenchmarkAKITrustedAuthoritiesChecker_Anchors checks a chain against
// a thousand trust anchors given as certificates.
func BenchmarkAKITrustedAuthoritiesChecker_Anchors(b *testing.B) {
	anchors := make([]*x509.Certificate, 1000)
	for i := range anchors {
		anchors[i], _ = testcert.CA(b, fmt.Sprint("ca ", i))
	}
	ca, caKey := testcert.CA(b, "issuing ca")
	anchors[len(anchors)/2] = ca
	leaf, _ := testcert.Leaf(b, "leaf", ca, caKey)
	checker := dcql.AKITrustedAuthoritiesChecker{Anchors: anchors}
	want := verifiedAKI(ca)
	chain := [][]byte{leaf.Raw}
	b.ReportAllocs()
	for b.Loop() {
		if err := checker.CheckTrustedAuthorities(context.Background(), want, chain); err != nil {
			b.Fatal(err)
		}
	}
}

// A checker's Anchors changed in place between checks are the anchors
// the next check uses: what a check keeps of them is for the same
// certificates only.
func TestAKITrustedAuthoritiesChecker_AnchorsChangedInPlace(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuing ca")
	other, _ := testcert.CA(t, "other ca")
	leaf, _ := testcert.Leaf(t, "leaf", ca, caKey)
	anchors := []*x509.Certificate{ca, other}
	checker := dcql.AKITrustedAuthoritiesChecker{Anchors: anchors}
	chain := [][]byte{leaf.Raw}
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), chain); err != nil {
		t.Fatalf("with the issuing CA among the anchors: %v", err)
	}
	anchors[0] = other
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), chain); err == nil {
		t.Fatal("passed after the issuing CA was replaced among the anchors")
	}
	anchors[0] = nil
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), chain); err == nil {
		t.Fatal("passed with a nil anchor, which Validate refuses")
	}
	anchors[0] = ca
	if err := checker.CheckTrustedAuthorities(context.Background(), verifiedAKI(ca), chain); err != nil {
		t.Fatalf("with the issuing CA back: %v", err)
	}
}
