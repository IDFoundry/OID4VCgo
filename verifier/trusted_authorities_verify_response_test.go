package verifier_test

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/sdjwtvc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// trustedAuthoritiesQuery is testIdentityQuery with a TrustedAuthorities
// restriction of type aki added — everything else identical.
func trustedAuthoritiesQuery(t *testing.T, aki string) dcql.Query {
	t.Helper()
	query := testIdentityQuery(t)
	query.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthoritiesQuery{
		{Type: dcql.TrustedAuthorityAKI, Values: []string{aki}},
	}
	return query
}

func TestVerifyResponse_ChecksTrustedAuthorities_Accepts(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, leafKey := verifier.ContractLeaf(t, "test-leaf", ca, caKey)
	aki := base64.RawURLEncoding.EncodeToString(leaf.AuthorityKeyId)

	query := trustedAuthoritiesQuery(t, aki)
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentationWithIssuerOpts(t, leafKey, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, v.ClientID(), built.Nonce)

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:              query,
		Response:           verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce:      built.Nonce,
		IssuerKeys:         fixedSDJWTVCIssuerKeyResolver{pub: &leafKey.PublicKey, alg: jose.ES256},
		MaxKeyBindingAge:   time.Hour,
		TrustedAuthorities: dcql.AKITrustedAuthoritiesChecker{},
	})
	testverify.RequireOneCredential(t, result, err, "identity_credential")
}

func TestVerifyResponse_ChecksTrustedAuthorities_RejectsWrongAKI(t *testing.T) {
	ca, caKey := verifier.ContractCA(t, "test-ca")
	leaf, leafKey := verifier.ContractLeaf(t, "test-leaf", ca, caKey)

	query := trustedAuthoritiesQuery(t, "not-the-right-aki")
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	fixture := newSDJWTVCPresentationWithIssuerOpts(t, leafKey, sdjwtvc.IssueOptions{IssuerCertificate: leaf}, v.ClientID(), built.Nonce)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:              query,
		Response:           verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {fixture.compact}}},
		ExpectedNonce:      built.Nonce,
		IssuerKeys:         fixedSDJWTVCIssuerKeyResolver{pub: &leafKey.PublicKey, alg: jose.ES256},
		MaxKeyBindingAge:   time.Hour,
		TrustedAuthorities: dcql.AKITrustedAuthoritiesChecker{},
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error (aki does not match)")
	}
}

// TestVerifyResponse_RejectsMissingTrustedAuthoritiesDependency proves
// VerifyResponse fails closed — rather than silently skipping the
// restriction — when a Credential Query declares TrustedAuthorities
// but req.TrustedAuthorities is nil.
func TestVerifyResponse_RejectsMissingTrustedAuthoritiesDependency(t *testing.T) {
	query := trustedAuthoritiesQuery(t, "anything")
	_, _, v := newTestVerifierWithConfig(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:            query,
		Response:         verifier.ParsedResponse{VPToken: map[string][]string{"identity_credential": {}}},
		ExpectedNonce:    built.Nonce,
		MaxKeyBindingAge: time.Hour,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error (trusted_authorities dependency missing)")
	}
}

// TestVerifyMdocResponse_RejectsMissingTrustedAuthoritiesDependency
// mirrors TestVerifyResponse_RejectsMissingTrustedAuthoritiesDependency
// for the "mso_mdoc" call path (verifyMdocPresentation's own separate
// TrustedAuthorities check) — same fail-closed gate, different format.
func TestVerifyMdocResponse_RejectsMissingTrustedAuthoritiesDependency(t *testing.T) {
	query := testmdoc.Query(t)
	query.Credentials[0].TrustedAuthorities = []dcql.TrustedAuthoritiesQuery{
		{Type: dcql.TrustedAuthorityAKI, Values: []string{"anything"}},
	}
	mf := newMdocVerifyFixture(t)
	mf.query = query

	if _, err := mf.verify(t, mf.nonce); err == nil {
		t.Fatalf("VerifyResponse = nil error, want error (trusted_authorities dependency missing)")
	}
}
