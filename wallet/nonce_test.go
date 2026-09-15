package wallet_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func testNonceEndpoint(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/nonce", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestRequestNonce(t *testing.T) {
	w := newTestWallet(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", req.Method)
		}
		return jsonResponse([]byte(`{"c_nonce":"fresh-nonce"}`)), nil
	})

	result, err := w.RequestNonce(context.Background(), testNonceEndpoint(t))
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if result.CNonce != "fresh-nonce" {
		t.Errorf("CNonce = %q, want %q", result.CNonce, "fresh-nonce")
	}
}

func TestRequestNonce_RejectsMissingCNonce(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		return jsonResponse([]byte(`{}`)), nil
	})
	if _, err := w.RequestNonce(context.Background(), testNonceEndpoint(t)); err == nil {
		t.Fatalf("RequestNonce = nil error, want error")
	}
}

func TestRequestNonce_PropagatesTransportError(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("simulated network failure")
	})
	if _, err := w.RequestNonce(context.Background(), testNonceEndpoint(t)); err == nil {
		t.Fatalf("RequestNonce = nil error, want error")
	}
}
