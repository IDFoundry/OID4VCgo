package wallet_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A public client's refresh carries no client authentication, only the
// refresh token and a DPoP proof from the key it's bound to, retried
// once on a DPoP nonce challenge.
func TestRequestRefreshToken(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var forms []url.Values
	var proofs []string
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		form, _ := url.ParseQuery(string(body))
		forms = append(forms, form)
		proofs = append(proofs, req.Header.Get("DPoP"))
		if req.Header.Get("OAuth-Client-Attestation") != "" || req.Header.Get("Authorization") != "" {
			t.Error("the refresh authenticates a client")
		}
		if len(forms) == 1 {
			return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Dpop-Nonce": {"n-1"}},
				Body: io.NopCloser(strings.NewReader(`{"error":"use_dpop_nonce"}`))}, nil
		}
		return jsonResponse([]byte(`{"access_token":"at-2","token_type":"DPoP","expires_in":300,"refresh_token":"rt-2"}`)), nil
	})
	got, err := w.RequestRefreshToken(context.Background(), testTokenEndpoint(t), wallet.RefreshTokenRequest{
		RefreshToken: fapi.NewSecret("rt-1"), DPoPKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken.Reveal() != "at-2" || got.RefreshToken.Reveal() != "rt-2" || !got.HasExpiresIn {
		t.Errorf("result = %+v", got)
	}
	if len(forms) != 2 || forms[1].Get("grant_type") != "refresh_token" || forms[1].Get("refresh_token") != "rt-1" || forms[1].Get("client_id") != "" {
		t.Errorf("forms = %v", forms)
	}
	if _, claims := jwtParts(t, proofs[1]); claims["nonce"] != "n-1" {
		t.Errorf("retried proof's nonce = %v, want n-1", claims["nonce"])
	}
}

// A Bearer grant's refresh sends no DPoP proof, and a refused refresh
// token is invalid_grant.
func TestRequestRefreshToken_BearerRefused(t *testing.T) {
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		if req.Header.Get("DPoP") != "" {
			t.Error("a Bearer grant's refresh carries a DPoP proof")
		}
		return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{},
			Body: io.NopCloser(strings.NewReader(`{"error":"invalid_grant"}`))}, nil
	})
	_, err := w.RequestRefreshToken(context.Background(), testTokenEndpoint(t), wallet.RefreshTokenRequest{RefreshToken: fapi.NewSecret("rt-1")})
	var protocol *wallet.Error
	if !errors.As(err, &protocol) || protocol.Code != "invalid_grant" {
		t.Errorf("err = %v, want invalid_grant", err)
	}
	if _, err := w.RequestRefreshToken(context.Background(), testTokenEndpoint(t), wallet.RefreshTokenRequest{}); err == nil {
		t.Error("a refresh with no refresh token accepted")
	}
}

func TestRevokeToken(t *testing.T) {
	var form url.Values
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		form, _ = url.ParseQuery(string(body))
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}, nil
	})
	if err := w.RevokeToken(context.Background(), testTokenEndpoint(t), fapi.NewSecret("rt-1"), "refresh_token"); err != nil {
		t.Fatal(err)
	}
	if form.Get("token") != "rt-1" || form.Get("token_type_hint") != "refresh_token" || form.Get("client_id") != "" {
		t.Errorf("form = %v", form)
	}
}

func TestBearerResourceClient(t *testing.T) {
	var auth, dpop string
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		auth, dpop = req.Header.Get("Authorization"), req.Header.Get("DPoP")
		return jsonResponse([]byte(`{}`)), nil
	})
	req, _ := http.NewRequest(http.MethodPost, "https://issuer.example/credential", nil)
	if _, err := w.BearerResourceClient(fapi.NewSecret("at-1")).Do(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer at-1" || dpop != "" {
		t.Errorf("Authorization %q, DPoP %q", auth, dpop)
	}
}

func TestCanonicalTokenType(t *testing.T) {
	for in, want := range map[string]string{"DPoP": "DPoP", "dpop": "DPoP", "Bearer": "Bearer", "bearer": "Bearer", "N_A": "", "": ""} {
		got, err := wallet.CanonicalTokenType(in)
		if got != want || (err == nil) != (want != "") {
			t.Errorf("CanonicalTokenType(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
