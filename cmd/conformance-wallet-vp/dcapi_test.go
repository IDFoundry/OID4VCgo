package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const testDCAPIOrigin = "https://suite.example"

// postDCAPI calls handleDCAPI as the driver does.
func postDCAPI(t *testing.T, s *server, protocol string, data any) dcapiAnswer {
	t.Helper()
	body, err := json.Marshal(map[string]any{"protocol": protocol, "data": data, "origin": testDCAPIOrigin})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.handleDCAPI(rec, httptest.NewRequest(http.MethodPost, "/dcapi", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	var answer dcapiAnswer
	if err := json.Unmarshal(rec.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

func newDCAPIVerifier(t *testing.T, s *server) (*verifier.Verifier, *x509.Certificate) {
	t.Helper()
	ca, caKey := testcert.CA(t, "conformance-wallet-vp dcapi test CA")
	cert, key := testcert.Leaf(t, "conformance-wallet-vp dcapi test verifier", ca, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	s.trust = wallet.X5CVerifierRoots{Roots: roots}
	responseURI, err := fapi.ParseEndpointURL("https://verifier.example/response")
	if err != nil {
		t.Fatal(err)
	}
	v, err := verifier.New(verifier.Config{
		Assurance: verifier.AssuranceDevelopment, ClientCertificate: cert, ResponseURI: responseURI, SigningAlg: jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: key, Random: rand.Reader})
	if err != nil {
		t.Fatal(err)
	}
	return v, cert
}

// A signed DC API request is answered with a dc_api.jwt response the
// Verifier verifies, bound to the origin.
func TestHandleDCAPI_Presents(t *testing.T) {
	s, issuerCA := setupWalletUnderTest(t)
	v, _ := newDCAPIVerifier(t, s)
	query := newTestQuery(t, "urn:eudi:pid:1")
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{Query: query, ExpectedOrigins: []string{testDCAPIOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	answer := postDCAPI(t, s, wallet.DCAPIProtocolSigned, map[string]string{"request": built.RequestObject})
	if answer.SentError != "" || answer.Result.Exception != nil || answer.Result.Protocol != wallet.DCAPIProtocolSigned {
		t.Fatalf("answer = %+v", answer)
	}
	var data struct{ Response string }
	if err := json.Unmarshal(answer.Result.Data, &data); err != nil {
		t.Fatal(err)
	}
	parsed, err := v.ParseDirectPostJWTResponse(data.Response, built.ResponseDecryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuerCA)
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: parsed, ExpectedNonce: built.Nonce, Origin: testDCAPIOrigin, ExpectedOrigins: []string{testDCAPIOrigin}, MaxKeyBindingAge: time.Hour,
		IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots},
	})
	if err != nil || len(result.Credentials) != 1 {
		t.Fatalf("VerifyResponse = %+v, %v", result, err)
	}
}

// A request for another origin is refused without an answer, as the
// browser's promise rejects; one the wallet can't answer gets an error
// response, encrypted for the Verifier.
func TestHandleDCAPI_Refusals(t *testing.T) {
	s, _ := setupWalletUnderTest(t)
	v, _ := newDCAPIVerifier(t, s)
	elsewhere, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: newTestQuery(t, "urn:eudi:pid:1"), ExpectedOrigins: []string{"https://elsewhere.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if answer := postDCAPI(t, s, wallet.DCAPIProtocolSigned, map[string]string{"request": elsewhere.RequestObject}); answer.Result.Exception == nil {
		t.Errorf("another origin's request: %+v, want a refusal", answer)
	}

	other, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: newTestQuery(t, "urn:example:other:1"), ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	answer := postDCAPI(t, s, wallet.DCAPIProtocolSigned, map[string]string{"request": other.RequestObject})
	var data struct{ Response string }
	if answer.SentError != "access_denied" || json.Unmarshal(answer.Result.Data, &data) != nil {
		t.Fatalf("no matching credential: %+v, want access_denied", answer)
	}
	_, err = v.ParseDirectPostJWTResponse(data.Response, other.ResponseDecryptionKey)
	var respErr *verifier.ResponseError
	if !errors.As(err, &respErr) || respErr.Code != "access_denied" {
		t.Errorf("the Verifier read %v, want access_denied", err)
	}
}
