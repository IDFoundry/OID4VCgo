package wallet_test

import (
	"context"
	"crypto"
	"encoding/json"
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
		Query: query, Response: parsed, ExpectedNonce: built.Nonce, Origin: testDCAPIOrigin, ExpectedOrigins: []string{testDCAPIOrigin}, MaxKeyBindingAge: time.Hour,
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

// resign re-signs requestObject's payload, changed by mutate, with key,
// keeping its typ and x5c.
func resign(t *testing.T, key crypto.Signer, requestObject string, mutate func(claims map[string]any)) string {
	t.Helper()
	header, payload, err := jose.DecodeUnverified(requestObject)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	mutate(claims)
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	signed, err := jose.Sign(jose.ES256, key, map[string]any{"typ": header["typ"], "x5c": header["x5c"]}, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return signed
}

// TestParseRequests_RequireTheirResponseTypeAndMode: each parser answers
// only a vp_token request in its own Response Mode. The redirect flow
// refuses others with a RequestRejectedError it can send back; the DC
// API flow refuses them outright.
func TestParseRequests_RequireTheirResponseTypeAndMode(t *testing.T) {
	key, cert, trust := testVerifierSignerAndCert(t)
	v := newTestVerifierWith(t, key, cert)
	redirect, err := v.BuildAuthorizationRequest(verifier.BuildAuthorizationRequestRequest{Query: testQuery(t)})
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mutate   func(map[string]any)
		wantCode string
	}{
		"response_type code":   {func(c map[string]any) { c["response_type"] = "code" }, "unsupported_response_type"},
		"no response_type":     {func(c map[string]any) { delete(c, "response_type") }, "unsupported_response_type"},
		"response_mode plain":  {func(c map[string]any) { c["response_mode"] = "direct_post" }, "invalid_request"},
		"response_mode dc_api": {func(c map[string]any) { c["response_mode"] = "dc_api.jwt" }, "invalid_request"},
		"no response_mode":     {func(c map[string]any) { delete(c, "response_mode") }, "invalid_request"},
	} {
		_, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: resign(t, key, redirect.RequestObject, tc.mutate), ClientID: v.ClientID(), VerifierTrust: trust,
		})
		var rejected *wallet.RequestRejectedError
		if !errors.As(err, &rejected) || rejected.Code != tc.wantCode || rejected.ResponseURI == "" {
			t.Errorf("redirect flow, %s: err = %v, want a RequestRejectedError %q to send back", name, err, tc.wantCode)
		}
	}

	dcapi, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: testQuery(t), ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"response_type code": func(c map[string]any) { c["response_type"] = "code" },
		"no response_type":   func(c map[string]any) { delete(c, "response_type") },
	} {
		_, err := wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
			Request: resign(t, key, dcapi.RequestObject, mutate), Origin: testDCAPIOrigin, VerifierTrust: trust,
		})
		if err == nil || !strings.Contains(err.Error(), "response_type") {
			t.Errorf("DC API, %s: err = %v, want response_type refused", name, err)
		}
	}
	_, err = wallet.ParseDCAPIRequest(wallet.ParseDCAPIRequestParams{
		Request: resign(t, key, dcapi.RequestObject, func(c map[string]any) { c["transaction_data"] = []string{"e30"} }),
		Origin:  testDCAPIOrigin, VerifierTrust: trust,
	})
	if err == nil || !strings.HasPrefix(err.Error(), "wallet: parse dc api request:") {
		t.Errorf("DC API transaction_data: err = %v, want it named as ParseDCAPIRequest's", err)
	}
}

// TestWallet_ParseDCAPIRequest uses the Wallet's own VerifierTrust.
func TestWallet_ParseDCAPIRequest(t *testing.T) {
	v, _, trust := newTestVerifier(t)
	built, err := v.BuildDCAPIAuthorizationRequest(verifier.BuildDCAPIAuthorizationRequestRequest{
		Query: testQuery(t), ExpectedOrigins: []string{testDCAPIOrigin},
	})
	if err != nil {
		t.Fatal(err)
	}
	if req, err := newTestWalletTrusting(t, trust, nil).ParseDCAPIRequest(built.RequestObject, testDCAPIOrigin); err != nil || req.Origin != testDCAPIOrigin {
		t.Errorf("trusting wallet: %+v, %v", req, err)
	}
	_, _, otherTrust := newTestVerifier(t)
	if _, err := newTestWalletTrusting(t, otherTrust, nil).ParseDCAPIRequest(built.RequestObject, testDCAPIOrigin); err == nil || !strings.Contains(err.Error(), "untrusted verifier") {
		t.Errorf("wallet trusting another CA: err = %v, want the Verifier untrusted", err)
	}
	if _, err := newTestWalletTrusting(t, nil, nil).ParseDCAPIRequest(built.RequestObject, testDCAPIOrigin); err == nil {
		t.Error("a wallet without VerifierTrust parsed a DC API request")
	}
}
