package wallet_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// jwtParts decodes a compact JWT's header and payload without verifying.
func jwtParts(t *testing.T, jwt string) (header, claims map[string]any) {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWT: %q", jwt)
	}
	for i, out := range []*map[string]any{&header, &claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	return header, claims
}

// fakeAttestationSource hands out the attestation and a numbered PoP.
type fakeAttestationSource struct{ calls int }

func (f *fakeAttestationSource) ClientAttestationHeaders(context.Context) (string, string, error) {
	f.calls++
	return "wallet-attestation-jwt", fmt.Sprintf("pop-%d", f.calls), nil
}

// TestRequestPreAuthorizedCodeToken_ClientAttestation: the Token
// Request carries the Wallet Attestation and a fresh PoP from its source
// on each attempt, including the retry after a DPoP nonce challenge.
func TestRequestPreAuthorizedCodeToken_ClientAttestation(t *testing.T) {
	var attestations, pops []string
	attempt := 0
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		attestations = append(attestations, req.Header.Get("OAuth-Client-Attestation"))
		pops = append(pops, req.Header.Get("OAuth-Client-Attestation-PoP"))
		attempt++
		if attempt == 1 {
			return &http.Response{StatusCode: http.StatusBadRequest, Header: http.Header{"Dpop-Nonce": {"n-1"}},
				Body: io.NopCloser(strings.NewReader(`{"error":"use_dpop_nonce"}`))}, nil
		}
		return jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP"}`)), nil
	})
	src := &fakeAttestationSource{}
	if _, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123", DPoPKey: testP256Key(t), ClientAttestation: src,
	}); err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if want := []string{"pop-1", "pop-2"}; strings.Join(pops, ",") != strings.Join(want, ",") ||
		attestations[0] != "wallet-attestation-jwt" || attestations[1] != "wallet-attestation-jwt" {
		t.Errorf("sent attestations %v, PoPs %v; want the attestation and a fresh PoP on each attempt", attestations, pops)
	}
}

// TestDPoPResourceClient: each request carries the token and a DPoP
// proof bound to it (ath) for its URL; a nonce challenge is answered by
// one retry with the same body, and the nonce is reused afterwards.
func TestDPoPResourceClient(t *testing.T) {
	type sent struct{ auth, proof, body string }
	var requests []sent
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(req.Body)
		requests = append(requests, sent{req.Header.Get("Authorization"), req.Header.Get("DPoP"), string(body)})
		if len(requests) == 1 {
			return &http.Response{StatusCode: http.StatusUnauthorized, Body: http.NoBody, Header: http.Header{
				"Www-Authenticate": {`DPoP error="use_dpop_nonce"`}, "Dpop-Nonce": {"n-1"},
			}}, nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Header: http.Header{"Dpop-Nonce": {"n-2"}}}, nil
	})
	rc := w.DPoPResourceClient(fapi.NewSecret("tok-1"), testP256Key(t))
	post := func() {
		req, err := http.NewRequest(http.MethodPost, "https://issuer.example.com/credential?x=1", bytes.NewReader([]byte(`{"a":1}`)))
		if err != nil {
			t.Fatal(err)
		}
		res, err := rc.Do(context.Background(), req)
		if err != nil || res.StatusCode != http.StatusOK {
			t.Fatalf("Do = %v, %v", res, err)
		}
	}
	post()
	post()
	if len(requests) != 3 {
		t.Fatalf("sent %d requests, want a challenged one, its retry, then one more", len(requests))
	}
	wantNonces := []any{nil, "n-1", "n-2"}
	for i, r := range requests {
		_, claims := jwtParts(t, r.proof)
		if r.auth != "DPoP tok-1" || r.body != `{"a":1}` || claims["htm"] != "POST" ||
			claims["htu"] != "https://issuer.example.com/credential" || claims["ath"] != wallet.DPoPAccessTokenHash("tok-1") ||
			claims["nonce"] != wantNonces[i] {
			t.Errorf("request %d: %+v, proof claims %v", i, r, claims)
		}
	}

	req, err := http.NewRequest(http.MethodPost, "https://issuer.example.com/credential", io.NopCloser(strings.NewReader("x")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Do(context.Background(), req); err == nil {
		t.Error("a request with a body that can't be replayed was sent")
	}
}
