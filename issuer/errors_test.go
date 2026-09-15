package issuer_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/issuer"
)

func TestRequestCredential_ErrorFields(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{}, issuer.CredentialRequest{
		CredentialConfigurationID: "NoSuchConfig",
	})
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error", err)
	}
	if ierr.Code() != issuer.ErrorUnknownCredentialConfig {
		t.Errorf("Code = %q", ierr.Code())
	}
	if ierr.HTTPStatus() != 400 {
		t.Errorf("HTTPStatus = %d, want 400", ierr.HTTPStatus())
	}
	if ierr.PublicDescription() == "" {
		t.Errorf("PublicDescription is empty")
	}
	if ierr.Error() == "" {
		t.Errorf("Error() is empty")
	}
	if ierr.Unwrap() != nil {
		t.Errorf("Unwrap = %v, want nil (no underlying cause for this error)", ierr.Unwrap())
	}

	rec := httptest.NewRecorder()
	ierr.WriteJSON(rec)
	if rec.Code != 400 {
		t.Errorf("HTTP status = %d, want 400", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if rec.Body.Len() == 0 {
		t.Errorf("response body is empty")
	}
}

func TestRequestCredential_ErrorWithCause(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	nonce := f.issueNonce(t)
	proof := buildJWTProof(t, testP256Key(t), testIssuer, nonce)
	tampered := tamperJWTSignature(t, proof)

	_, err := requestSDJWTWithProof(f, oid4vci.ProofTypeJWT, tampered)
	var ierr *issuer.Error
	if !errors.As(err, &ierr) {
		t.Fatalf("error = %v, want *issuer.Error", err)
	}
	if ierr.Unwrap() == nil {
		t.Errorf("Unwrap = nil, want the underlying signature-verification error")
	}
	if ierr.Error() == "" {
		t.Errorf("Error() is empty")
	}
}
