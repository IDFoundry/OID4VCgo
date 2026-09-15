package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo/credential/mdoc"
	"github.com/idfoundry/oid4vcigo/dcql"
	"github.com/idfoundry/oid4vcigo/internal/cose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
	"github.com/idfoundry/oid4vcigo/oid4vpmdoc"
	"github.com/idfoundry/oid4vcigo/verifier"
)

const testMdocDocType = "org.iso.18013.5.1.mDL"

// fixedMdocIssuerKeyResolver always resolves to the one issuer key a
// test signed with — the mdoc analog of fixedSDJWTVCIssuerKeyResolver.
type fixedMdocIssuerKeyResolver struct {
	pub crypto.PublicKey
	alg cose.Alg
}

func (r fixedMdocIssuerKeyResolver) ResolveMdocIssuerKey(context.Context, [][]byte, string) (crypto.PublicKey, cose.Alg, error) {
	return r.pub, r.alg, nil
}

// responseEncryptionThumbprintBytes computes the RFC 7638 SHA-256 JWK
// thumbprint of key's own public key as raw bytes — exactly what
// verifyMdocPresentation itself recomputes from
// VerifyResponseRequest.ResponseEncryptionKey, so a test presentation
// built with it produces the identical SessionTranscriptBytes
// verifier.VerifyResponse will reconstruct.
func responseEncryptionThumbprintBytes(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	j, err := jwk.Marshal(&key.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}
	thumbprint, err := j.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil {
		t.Fatalf("decode thumbprint: %v", err)
	}
	return raw
}

// mdocPresentationFixture is a real, freshly issued and presented
// "mso_mdoc" credential — a base64url-encoded DeviceResponse whose own
// DeviceSigned is bound to the exact clientID/nonce/responseURI/
// thumbprint a real verifier.VerifyResponse call will reconstruct.
type mdocPresentationFixture struct {
	issuerKey *ecdsa.PrivateKey
	presented string
}

func newMdocPresentation(t *testing.T, clientID, nonce, responseURI string, thumbprint []byte) mdocPresentationFixture {
	t.Helper()
	issuerKey := testP256Key(t)
	deviceKey := testP256Key(t)
	cert := testcert.SelfSigned(t, "mdoc test issuer", &issuerKey.PublicKey, issuerKey)

	signed := time.Now()
	issuerSigned, err := mdoc.Issue(issuerKey, cose.ES256, mdoc.Claims{
		DocType: testMdocDocType,
		NameSpaces: map[string]map[string]interface{}{
			"org.iso.18013.5.1": {"given_name": "Alice", "family_name": "Doe"},
		},
		DeviceKey:  &deviceKey.PublicKey,
		Signed:     signed,
		ValidFrom:  signed,
		ValidUntil: signed.Add(24 * time.Hour),
	}, mdoc.IssueOptions{X5Chain: [][]byte{cert.Raw}})
	if err != nil {
		t.Fatalf("mdoc.Issue: %v", err)
	}

	sessionTranscriptBytes, err := oid4vpmdoc.BuildSessionTranscriptBytes(oid4vpmdoc.HandoverParams{
		ClientID: clientID, Nonce: nonce, ResponseURI: responseURI, ResponseEncryptionJWKThumbprint: thumbprint,
	})
	if err != nil {
		t.Fatalf("BuildSessionTranscriptBytes: %v", err)
	}
	deviceSigned, err := mdoc.SignDeviceSignature(deviceKey, cose.ES256, sessionTranscriptBytes, testMdocDocType, map[string]map[string]interface{}{})
	if err != nil {
		t.Fatalf("mdoc.SignDeviceSignature: %v", err)
	}

	deviceResponseBytes, err := oid4vpmdoc.MarshalDeviceResponse(oid4vpmdoc.Document{
		DocType: testMdocDocType, IssuerSigned: issuerSigned, DeviceSigned: deviceSigned,
	})
	if err != nil {
		t.Fatalf("MarshalDeviceResponse: %v", err)
	}
	return mdocPresentationFixture{issuerKey: issuerKey, presented: base64.RawURLEncoding.EncodeToString(deviceResponseBytes)}
}

func testMdocQuery(t *testing.T) dcql.Query {
	t.Helper()
	meta, err := dcql.NewMdocMeta(dcql.MdocMeta{DoctypeValue: testMdocDocType})
	if err != nil {
		t.Fatalf("NewMdocMeta: %v", err)
	}
	return dcql.Query{Credentials: []dcql.CredentialQuery{{
		ID: "mdl", Format: mdoc.CredentialFormat, Meta: meta,
		Claims: []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey("given_name")}}},
	}}}
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
	query := testMdocQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	thumbprint := responseEncryptionThumbprintBytes(t, built.ResponseDecryptionKey)
	fixture := newMdocPresentation(t, v.ClientID(), built.Nonce, cfg.ResponseURI.String(), thumbprint)

	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {fixture.presented}}},
		ExpectedNonce:         built.Nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: cose.ES256},
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
	query := testMdocQuery(t)
	built, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	thumbprint := responseEncryptionThumbprintBytes(t, built.ResponseDecryptionKey)
	fixture := newMdocPresentation(t, v.ClientID(), "wrong-nonce", cfg.ResponseURI.String(), thumbprint)

	_, err = v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query:                 query,
		Response:              verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {fixture.presented}}},
		ExpectedNonce:         built.Nonce,
		MdocIssuerKeys:        fixedMdocIssuerKeyResolver{pub: &fixture.issuerKey.PublicKey, alg: cose.ES256},
		ResponseEncryptionKey: built.ResponseDecryptionKey,
	})
	if err == nil {
		t.Fatalf("VerifyResponse = nil error, want error")
	}
}

// rejectCaseMdocMissingDependency builds a VerifyResponseRequest for
// testMdocQuery missing exactly one of MdocIssuerKeys/
// ResponseEncryptionKey — both are checked before the (irrelevant
// here) presented content is even decoded, so a placeholder string is
// enough.
func rejectCaseMdocMissingDependency(t *testing.T, v *verifier.Verifier, nonce string, missingResponseEncryptionKey bool) verifier.VerifyResponseRequest {
	t.Helper()
	req := verifier.VerifyResponseRequest{
		Query: testMdocQuery(t), ExpectedNonce: nonce,
		Response: verifier.ParsedResponse{VPToken: map[string][]string{"mdl": {"irrelevant"}}},
	}
	if missingResponseEncryptionKey {
		req.MdocIssuerKeys = fixedMdocIssuerKeyResolver{}
	} else {
		req.ResponseEncryptionKey = testP256Key(t)
	}
	return req
}
