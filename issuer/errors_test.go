package issuer_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func TestRequestCredential_ErrorFields(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.CredentialRequest{
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

// TestWriteError_IssuerError proves WriteError delegates to the
// *issuer.Error's own WriteJSON when err is one — same status/body a
// direct ierr.WriteJSON(rec) call would produce.
func TestWriteError_IssuerError(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	_, err := f.iss.RequestCredential(context.Background(), issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client")}, issuer.CredentialRequest{
		CredentialConfigurationID: "NoSuchConfig",
	})
	if err == nil {
		t.Fatalf("RequestCredential: want an error, got nil")
	}

	rec := httptest.NewRecorder()
	issuer.WriteError(rec, err)
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

// TestWriteError_FallsBackForNonIssuerError proves WriteError falls
// back to a generic 500 for an error that isn't a *issuer.Error — the
// one case this package can't itself attribute to the request.
func TestWriteError_FallsBackForNonIssuerError(t *testing.T) {
	rec := httptest.NewRecorder()
	issuer.WriteError(rec, errors.New("boom"))
	if rec.Code != 500 {
		t.Errorf("HTTP status = %d, want 500", rec.Code)
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
