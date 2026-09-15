package wallet_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func decodeDPoPProofForTest(t *testing.T, proof string) (map[string]any, []byte) {
	t.Helper()
	header, payload, err := jose.DecodeUnverified(proof)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	return header, payload
}

func testTokenEndpoint(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/token", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func newTestWalletWithHTTP(t *testing.T, do func(*http.Request) (*http.Response, error)) *wallet.Wallet {
	t.Helper()
	deps := validDependencies()
	deps.HTTP = fakeHTTPClient{do: do}
	w, err := wallet.New(validConfig(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func TestRequestPreAuthorizedCodeToken_Success(t *testing.T) {
	var sentForm url.Values
	var sentDPoP string
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		sentForm = req.Form
		sentDPoP = req.Header.Get("DPoP")
		return jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP","expires_in":3600}`)), nil
	})

	result, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		TxCode:            "493536",
		DPoPKey:           testP256Key(t),
	})
	if err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if result.AccessToken.Reveal() != "tok-1" {
		t.Errorf("AccessToken = %q, want tok-1", result.AccessToken.Reveal())
	}
	if result.TokenType != "DPoP" {
		t.Errorf("TokenType = %q, want DPoP", result.TokenType)
	}
	if !result.HasExpiresIn || result.ExpiresIn != time.Hour {
		t.Errorf("ExpiresIn = %v (has=%v), want 1h", result.ExpiresIn, result.HasExpiresIn)
	}

	if sentForm.Get("grant_type") != wallet.PreAuthorizedCodeGrantType {
		t.Errorf("grant_type = %q, want %q", sentForm.Get("grant_type"), wallet.PreAuthorizedCodeGrantType)
	}
	if sentForm.Get("pre-authorized_code") != "abc123" {
		t.Errorf("pre-authorized_code = %q", sentForm.Get("pre-authorized_code"))
	}
	if sentForm.Get("tx_code") != "493536" {
		t.Errorf("tx_code = %q", sentForm.Get("tx_code"))
	}
	if sentDPoP == "" {
		t.Errorf("DPoP header is empty")
	}
}

func TestRequestPreAuthorizedCodeToken_OmitsTxCodeWhenEmpty(t *testing.T) {
	var sentForm url.Values
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		if err := req.ParseForm(); err != nil {
			t.Fatalf("ParseForm: %v", err)
		}
		sentForm = req.Form
		return jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP"}`)), nil
	})

	if _, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	}); err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if sentForm.Has("tx_code") {
		t.Errorf("tx_code = %q, want absent", sentForm.Get("tx_code"))
	}
}

func TestRequestPreAuthorizedCodeToken_RetriesOnDPoPNonceChallenge(t *testing.T) {
	var seenNonces []string
	calls := 0
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		calls++
		var claims struct {
			Nonce string `json:"nonce"`
		}
		_, payload := decodeDPoPProofForTest(t, req.Header.Get("DPoP"))
		if err := json.Unmarshal(payload, &claims); err != nil {
			t.Fatalf("unmarshal dpop payload: %v", err)
		}
		seenNonces = append(seenNonces, claims.Nonce)

		if calls == 1 {
			res := jsonResponse([]byte(`{"error":"use_dpop_nonce"}`))
			res.StatusCode = http.StatusBadRequest
			res.Header.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			res.Header.Set("DPoP-Nonce", "fresh-nonce")
			return res, nil
		}
		return jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP"}`)), nil
	})

	result, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	})
	if err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if result.AccessToken.Reveal() != "tok-1" {
		t.Errorf("AccessToken = %q", result.AccessToken.Reveal())
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if seenNonces[0] != "" {
		t.Errorf("first call nonce = %q, want empty", seenNonces[0])
	}
	if seenNonces[1] != "fresh-nonce" {
		t.Errorf("second call nonce = %q, want fresh-nonce", seenNonces[1])
	}
}

func TestRequestPreAuthorizedCodeToken_DoesNotRetryTwice(t *testing.T) {
	calls := 0
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		calls++
		res := jsonResponse([]byte(`{"error":"use_dpop_nonce"}`))
		res.StatusCode = http.StatusBadRequest
		res.Header.Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
		res.Header.Set("DPoP-Nonce", fmt.Sprintf("nonce-%d", calls))
		return res, nil
	})

	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	})
	if err == nil {
		t.Fatalf("RequestPreAuthorizedCodeToken = nil error, want error")
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want exactly 2 (one retry, then give up)", calls)
	}
}

func TestRequestPreAuthorizedCodeToken_RejectsMissingPreAuthorizedCode(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		DPoPKey: testP256Key(t),
	})
	if err == nil {
		t.Fatalf("RequestPreAuthorizedCodeToken = nil error, want error")
	}
}

func TestRequestPreAuthorizedCodeToken_RejectsMissingDPoPKey(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
	})
	if err == nil {
		t.Fatalf("RequestPreAuthorizedCodeToken = nil error, want error")
	}
}

func TestRequestPreAuthorizedCodeToken_RejectsMissingRandom(t *testing.T) {
	deps := validDependencies()
	deps.Random = nil
	deps.HTTP = fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	}}
	w, err := wallet.New(validConfig(), deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	})
	if err == nil {
		t.Fatalf("RequestPreAuthorizedCodeToken = nil error, want error")
	}
}

func TestRequestPreAuthorizedCodeToken_ParsesErrorResponse(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(*http.Request) (*http.Response, error) {
		res := jsonResponse([]byte(`{"error":"invalid_grant","error_description":"code expired"}`))
		res.StatusCode = http.StatusBadRequest
		return res, nil
	})
	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	})
	var werr *wallet.Error
	if !errors.As(err, &werr) {
		t.Fatalf("error = %v, want *wallet.Error", err)
	}
	if werr.Code != "invalid_grant" {
		t.Errorf("Code = %q, want invalid_grant", werr.Code)
	}
}

func TestRequestPreAuthorizedCodeToken_PropagatesTransportError(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("simulated network failure")
	})
	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123",
		DPoPKey:           testP256Key(t),
	})
	if err == nil {
		t.Fatalf("RequestPreAuthorizedCodeToken = nil error, want error")
	}
}
