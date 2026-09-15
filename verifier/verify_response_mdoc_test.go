package verifier_test

import (
	"context"
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
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

// presentMdocFixture builds a base64url-encoded DeviceResponse from
// testmdoc.Fixture f, its own DeviceSigned bound to the exact
// clientID/nonce/responseURI/thumbprint a real verifier.VerifyResponse
// call will reconstruct — the response-building half
// testmdoc.Fixture itself doesn't own, since only a specific test
// knows which aud/nonce a given case needs.
func presentMdocFixture(t *testing.T, f testmdoc.Fixture, clientID, nonce, responseURI string, thumbprint []byte) string {
	t.Helper()
	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: clientID, Nonce: nonce, ResponseURI: responseURI, ResponseEncryptionJWKThumbprint: thumbprint,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(f.DeviceKey, cose.ES256, sessionTranscriptBytes, testmdoc.DocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("SignDeviceSignature: %v", err)
	}
	deviceResponseBytes, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: testmdoc.DocType, IssuerSigned: f.IssuerSigned, DeviceSigned: deviceSigned,
	})
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(deviceResponseBytes)
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
	presented := presentMdocFixture(t, f, v.ClientID(), built.Nonce, cfg.ResponseURI.String(), thumbprint)

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
	presented := presentMdocFixture(t, f, v.ClientID(), "wrong-nonce", cfg.ResponseURI.String(), thumbprint)

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
