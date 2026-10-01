package wallet_test

import (
	"context"
	"crypto"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testverify"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

const testDCAPIOrigin = "https://verifier.example.com"

// TestParseDCAPIRequest_RoundTrip: a DC API request a real Verifier
// builds parses with the origin the platform reports, and the answer
// the documented path builds from it — PresentCredentials with that
// Origin, encrypted by BuildDirectPostResponse — verifies at the
// Verifier.
func TestParseDCAPIRequest_RoundTrip(t *testing.T) {
	v, _, trust := newTestVerifier(t)
	query := testPresentationQuery(t)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{"https://other.example.com", testDCAPIOrigin},
	})
	if err != nil {
		t.Fatalf("BuildDCAPIAuthorizationRequest: %v", err)
	}

	req, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
		Request: built.RequestObject, Origin: testDCAPIOrigin, VerifierTrust: trust,
	})
	if err != nil {
		t.Fatalf("ParseDCAPIRequest: %v", err)
	}
	if req.Origin != testDCAPIOrigin || req.ClientID != built.ClientID || req.Nonce != built.Nonce ||
		req.ResponseURI != "" || req.ResponseEncryptionKey == nil || len(req.Query.Credentials) != 1 {
		t.Fatalf("request = %+v", req)
	}

	fixture := newHeldSDJWTVC(t)
	vpToken, err := wallet.PresentCredentials(context.Background(), wallet.PresentationRequest{
		Query: req.Query, Credentials: []wallet.HeldCredential{fixture.held}, Origin: req.Origin, Nonce: req.Nonce,
		ResponseEncryptionKey: req.ResponseEncryptionKey,
	})
	if err != nil {
		t.Fatalf("PresentCredentials: %v", err)
	}
	response, err := wallet.BuildDirectPostResponse(wallet.BuildDirectPostResponseParams{
		VPToken: vpToken, EncryptionKey: req.ResponseEncryptionKey,
		EncryptionKeyID: req.ResponseEncryptionKeyID, EncryptionEnc: req.ResponseEncryptionEnc,
	})
	if err != nil {
		t.Fatalf("BuildDirectPostResponse: %v", err)
	}
	parsed, err := v.ParseDirectPostJWTResponse(response, built.ResponseDecryptionKey)
	if err != nil {
		t.Fatalf("ParseDirectPostJWTResponse: %v", err)
	}
	result, err := v.VerifyResponse(context.Background(), verifier.VerifyResponseRequest{
		Query: query, Response: parsed, ExpectedNonce: built.Nonce, Origin: testDCAPIOrigin, MaxKeyBindingAge: time.Hour,
		IssuerKeys: issuerKeyResolverFunc(func(context.Context, map[string]any, map[string]any) (crypto.PublicKey, jose.Alg, error) {
			return &fixture.issuerKey.PublicKey, jose.ES256, nil
		}),
	})
	testverify.RequireOneCredential(t, result, err, "identity_credential")
}

// TestParseDCAPIRequest_Refusals: a request is refused unless the
// platform's origin is one it expects, it asks for dc_api.jwt, and it's
// signed by a trusted Verifier.
func TestParseDCAPIRequest_Refusals(t *testing.T) {
	v, _, trust := newTestVerifier(t)
	query := testPresentationQuery(t)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: query, ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: query})
	if err != nil {
		t.Fatal(err)
	}
	_, _, otherTrust := newTestVerifier(t)

	for name, tc := range map[string]struct {
		params wallet.ParseDCAPIRequestParams
		want   string
	}{
		"another origin":        {wallet.ParseDCAPIRequestParams{Request: built.RequestObject, Origin: "https://attacker.example", VerifierTrust: trust}, "expected_origins"},
		"origin with a path":    {wallet.ParseDCAPIRequestParams{Request: built.RequestObject, Origin: testDCAPIOrigin + "/", VerifierTrust: trust}, "expected_origins"},
		"no origin":             {wallet.ParseDCAPIRequestParams{Request: built.RequestObject, VerifierTrust: trust}, "Origin is required"},
		"redirect-flow request": {wallet.ParseDCAPIRequestParams{Request: redirect.RequestObject, Origin: testDCAPIOrigin, VerifierTrust: trust}, "response_mode"},
		"untrusted verifier":    {wallet.ParseDCAPIRequestParams{Request: built.RequestObject, Origin: testDCAPIOrigin, VerifierTrust: otherTrust}, "untrusted verifier"},
		"no trust":              {wallet.ParseDCAPIRequestParams{Request: built.RequestObject, Origin: testDCAPIOrigin}, "VerifierTrust is required"},
		"not a JWS":             {wallet.ParseDCAPIRequestParams{Request: "not-a-jws", Origin: testDCAPIOrigin, VerifierTrust: trust}, "decode"},
	} {
		_, err := wallet.ParseDCAPIRequest(tc.params)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", name, err, tc.want)
		}
		var rejected *wallet.RequestRejectedError
		if errors.As(err, &rejected) {
			t.Errorf("%s: refused with a RequestRejectedError, before the request was trusted", name)
		}
	}
}
