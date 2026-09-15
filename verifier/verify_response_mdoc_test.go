package verifier_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/testmdoc"
	"github.com/idfoundry/oid4vcigo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcigo/verifier"
)

// fixedMdocIssuerKeyResolver always resolves to the one issuer key a
// test signed with — the mdoc analog of fixedSDJWTVCIssuerKeyResolver.
type fixedMdocIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg cose.Alg
}

func (r fixedMdocIssuerKeyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
	return r.pub, r.alg, nil
}

// TestVerifyMdocResponse drives a real end-to-end round trip: build a
// real Authorization Request, issue and present a real "mso_mdoc"
// credential bound to that exact clientID/nonce/responseURI/response-
// encryption-key thumbprint, and verify it via VerifyResponse.
func TestVerifyMdocResponse(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := testmdoc.Query(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	thumbprint := testmdoc.ResponseEncryptionThumbprint(t, built.ResponseDecryptionKey)
	f := testmdoc.Issue(t)
	presented := testmdoc.Present(t, f, oid4vpmdoc.HandoverParams{
		ClientID: v.ClientID(), Nonce: built.Nonce, ResponseURI: cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: thumbprint,
	})

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {presented}}},
		ExpectedNonce:         built.Nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &f.IssuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: built.ResponseDecryptionKey,
	})
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	if len(result.Credentials) != 1 {
		t.Fatalf("got %d credentials, want 1", len(result.Credentials))
	}
	if result.Credentials[0].CredentialQueryID != "mdl" {
		t.Errorf("CredentialQueryID = %q", result.Credentials[0].CredentialQueryID)
	}
	namespace, ok := result.Credentials[0].Claims["org.iso.18013.5.1"].(map[string]interface{})
	if !ok || namespace["given_name"] != "Alice" {
		t.Errorf("Claims[org.iso.18013.5.1] = %v", result.Credentials[0].Claims["org.iso.18013.5.1"])
	}
}

func TestVerifyMdocResponseRejectsWrongNonce(t *testing.T) {
	cfg, deps := validConfig(t)
	v, err := verifier.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	query := testmdoc.Query(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	thumbprint := testmdoc.ResponseEncryptionThumbprint(t, built.ResponseDecryptionKey)
	f := testmdoc.Issue(t)
	presented := testmdoc.Present(t, f, oid4vpmdoc.HandoverParams{
		ClientID: v.ClientID(), Nonce: "wrong-nonce", ResponseURI: cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: thumbprint,
	})

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {presented}}},
		ExpectedNonce:         built.Nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &f.IssuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: built.ResponseDecryptionKey,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// rejectCaseMdocMissingDependency builds a VerifyResponseRequest for
// testmdoc.Query missing exactly one of MdocIssuerKeys/
// ResponseEncryptionKey — both are checked before the (irrelevant
// here) presented content is even decoded, so a placeholder string is
// enough.
func rejectCaseMdocMissingDependency(t *testing.T, v *verifier.Verifier, nonce string, missingResponseEncryptionKey bool) verifier.VerifyResponseRequest {
	t.Helper()
	req := verifier.VerifyResponseRequest{
		Query: testmdoc.Query(t), ExpectedNonce: nonce,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"irrelevant"}}},
	}
	if missingResponseEncryptionKey {
		req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{}
	} else {
		req.ResponseEncryptionKey = testP256Key(t)
	}
	return req
}
