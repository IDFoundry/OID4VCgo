package verifier_test

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

func TestAKITrustedAuthoritiesChecker_AcceptsMatchingAKI(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, _ := verifier.ContractLeaf(t, "test-leaf", ca, caKey)
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{aki}}}
	err := verifier.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err != nil {
		t.Fatalf("CheckTrustedAuthorities: %v", err)
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsNonMatchingAKI(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, _ := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"not-the-right-aki"}}}
	err := verifier.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsNoAKIEntry(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, _ := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityETSITL, Values: []string{"something"}}}
	err := verifier.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (no aki entry present)")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsEmptyChain(t *testing.T) {
	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}}}
	err := verifier.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, nil)
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (no issuer chain)")
	}
}

func TestAKITrustedAuthoritiesChecker_RejectsLeafWithNoAKI(t *testing.T) {
	// A non-CA self-signed leaf gets no SubjectKeyId (Go's own
	// CreateCertificate only generates one for a CA template), and so
	// no AuthorityKeyId either — a real-world equivalent of a
	// certificate whose issuer genuinely never set the extension.
	leaf, _ := verifier.ContractSelfSignedLeaf(t, "test-self-signed")

	authorities := []dcql.TrustedAuthoritiesQuery{{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}}}
	err := verifier.AKITrustedAuthoritiesChecker{}.CheckTrustedAuthorities(context.Background(), authorities, [][]byte{leaf.Raw})
	if err == nil {
		t.Fatalf("CheckTrustedAuthorities = nil error, want error (leaf has no AKI extension)")
	}
}
