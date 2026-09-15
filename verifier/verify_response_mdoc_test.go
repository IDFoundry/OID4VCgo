package verifier_test

import (
	"context"
	"crypto"
	"testing"

	"github.com/idfoundry/oid4vcigo/dcql"
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

// mdocVerifyFixture bundles a real *verifier.Verifier, the DCQL query
// it was given, its own BuildAuthorizationRequest result, and a real
// issued "mso_mdoc" credential's own response-encryption thumbprint —
// the setup every VerifyResponse mdoc test needs before building its
// own Presentation with whichever aud/nonce that specific case wants.
type mdocVerifyFixture struct {
	v          *verifier.Verifier
	cfg        verifier.Config
	query      dcql.Query
	built      verifier.BuildAuthorizationRequestResult
	thumbprint []byte
	f          testmdoc.Fixture
}

func newMdocVerifyFixture(t *testing.T) mdocVerifyFixture {
	t.Helper()
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
	return mdocVerifyFixture{v: v, cfg: cfg, query: query, built: built, thumbprint: thumbprint, f: f}
}

// verify builds a Presentation bound to nonce (not necessarily
// mf.built.Nonce — a test deliberately mismatching it uses this to
// build one that won't validate) and calls VerifyResponse with it.
func (mf mdocVerifyFixture) verify(t *testing.T, nonce string) (verifier.VerifyResponseResult, error) {
	t.Helper()
	presented := testmdoc.Present(t, mf.f, oid4vpmdoc.HandoverParams{
		ClientID: mf.v.ClientID(), Nonce: nonce, ResponseURI: mf.cfg.ResponseURI.String(), ResponseEncryptionJWKThumbprint: mf.thumbprint,
	})
	return mf.v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 mf.query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {presented}}},
		ExpectedNonce:         mf.built.Nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &mf.f.IssuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: mf.built.ResponseDecryptionKey,
	})
}

// TestVerifyMdocResponse drives a real end-to-end round trip: build a
// real Authorization Request, issue and present a real "mso_mdoc"
// credential bound to that exact clientID/nonce/responseURI/response-
// encryption-key thumbprint, and verify it via VerifyResponse.
func TestVerifyMdocResponse(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	result, err := mf.verify(t, mf.built.Nonce)
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
	mf := newMdocVerifyFixture(t)
	if _, err := mf.verify(t, "wrong-nonce"); err == nil {
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
