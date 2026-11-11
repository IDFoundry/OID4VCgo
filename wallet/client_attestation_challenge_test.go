package wallet_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/idfoundry/fapigo/client"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// fapigo/client's Client takes a Challenge from a response it didn't
// send, so walletflow's pre-authorized code flow passes it one.
var _ wallet.AttestationChallengeObserver = (*client.Client)(nil)

// challengeSource hands out the attestation and a PoP naming the latest
// Challenge it was given, as fapigo/client's does.
type challengeSource struct {
	calls     int
	challenge string
}

func (c *challengeSource) ClientAttestationHeaders(context.Context) (string, string, error) {
	c.calls++
	return testWalletAttestation, fmt.Sprintf("pop-%d-%s", c.calls, c.challenge), nil
}

func (c *challengeSource) ObserveAttestationChallenge(header http.Header) {
	if v := header.Get("OAuth-Client-Attestation-Challenge"); v != "" {
		c.challenge = v
	}
}

// tokenServer answers each Token Request with the next of responses,
// recording the PoP and DPoP proof each request carried.
func tokenServer(t *testing.T, responses ...func() *http.Response) (*wallet.Wallet, *[]string, *[]string) {
	t.Helper()
	var pops, proofs []string
	w := newTestWalletWithHTTP(t, func(req *http.Request) (*http.Response, error) {
		pops = append(pops, req.Header.Get("OAuth-Client-Attestation-PoP"))
		proofs = append(proofs, req.Header.Get("DPoP"))
		if len(pops) > len(responses) {
			t.Fatalf("request %d: no response left", len(pops))
		}
		return responses[len(pops)-1](), nil
	})
	return w, &pops, &proofs
}

func errorResponse(code string, header http.Header) func() *http.Response {
	return func() *http.Response {
		return &http.Response{StatusCode: http.StatusBadRequest, Header: header,
			Body: io.NopCloser(strings.NewReader(`{"error":"` + code + `"}`))}
	}
}

func okResponse(header http.Header) func() *http.Response {
	return func() *http.Response {
		res := jsonResponse([]byte(`{"access_token":"tok-1","token_type":"DPoP"}`))
		for k, v := range header {
			res.Header[k] = v
		}
		return res
	}
}

func requestToken(w *wallet.Wallet, t *testing.T, src wallet.ClientAttestationSource) error {
	t.Helper()
	_, err := w.RequestPreAuthorizedCodeToken(context.Background(), testTokenEndpoint(t), wallet.PreAuthorizedCodeTokenRequest{
		PreAuthorizedCode: "abc123", DPoPKey: testP256Key(t), ClientAttestation: src,
	})
	return err
}

// TestRequestPreAuthorizedCodeToken_AttestationChallengeRetry: a
// use_attestation_challenge error with a Challenge header is answered
// by one retry whose fresh PoP carries that Challenge.
func TestRequestPreAuthorizedCodeToken_AttestationChallengeRetry(t *testing.T) {
	w, pops, _ := tokenServer(t,
		errorResponse("use_attestation_challenge", http.Header{"Oauth-Client-Attestation-Challenge": {"c-1"}}),
		okResponse(nil))
	if err := requestToken(w, t, &challengeSource{}); err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if got := strings.Join(*pops, ","); got != "pop-1-,pop-2-c-1" {
		t.Errorf("PoPs %s, want a first without a Challenge and a retry with c-1", got)
	}
}

// TestRequestPreAuthorizedCodeToken_ChallengeFromSuccess: a Challenge a
// successful response carries goes in the next request's PoP.
func TestRequestPreAuthorizedCodeToken_ChallengeFromSuccess(t *testing.T) {
	w, pops, _ := tokenServer(t,
		okResponse(http.Header{"Oauth-Client-Attestation-Challenge": {"c-2"}}),
		okResponse(nil))
	src := &challengeSource{}
	for range 2 {
		if err := requestToken(w, t, src); err != nil {
			t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
		}
	}
	if got := strings.Join(*pops, ","); got != "pop-1-,pop-2-c-2" {
		t.Errorf("PoPs %s, want the second to carry c-2", got)
	}
}

// TestRequestPreAuthorizedCodeToken_BothChallenges: a DPoP nonce
// challenge and an attestation challenge each get one retry, and the
// attestation retry carries the DPoP nonce its response supplied.
func TestRequestPreAuthorizedCodeToken_BothChallenges(t *testing.T) {
	w, pops, proofs := tokenServer(t,
		errorResponse("use_dpop_nonce", http.Header{"Dpop-Nonce": {"n-1"}}),
		errorResponse("use_attestation_challenge", http.Header{"Oauth-Client-Attestation-Challenge": {"c-1"}, "Dpop-Nonce": {"n-2"}}),
		okResponse(nil))
	if err := requestToken(w, t, &challengeSource{}); err != nil {
		t.Fatalf("RequestPreAuthorizedCodeToken: %v", err)
	}
	if got := strings.Join(*pops, ","); got != "pop-1-,pop-2-,pop-3-c-1" {
		t.Errorf("PoPs %s", got)
	}
	for i, want := range []any{nil, "n-1", "n-2"} {
		if _, claims := jwtParts(t, (*proofs)[i]); claims["nonce"] != want {
			t.Errorf("request %d: DPoP nonce %v, want %v", i, claims["nonce"], want)
		}
	}
}

// TestRequestPreAuthorizedCodeToken_AttestationChallengeOnce: a second
// attestation challenge isn't retried, and a source that can't take a
// Challenge gets none: the error is returned at once.
func TestRequestPreAuthorizedCodeToken_AttestationChallengeOnce(t *testing.T) {
	challenge := errorResponse("use_attestation_challenge", http.Header{"Oauth-Client-Attestation-Challenge": {"c-1"}})
	for _, tc := range []struct {
		name     string
		src      wallet.ClientAttestationSource
		requests int
	}{
		{"observer", &challengeSource{}, 2},
		{"plain source", &fakeAttestationSource{}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, pops, _ := tokenServer(t, challenge, challenge)
			err := requestToken(w, t, tc.src)
			var refused *wallet.Error
			if !errors.As(err, &refused) || refused.Code != "use_attestation_challenge" {
				t.Fatalf("err = %v, want the use_attestation_challenge error", err)
			}
			if len(*pops) != tc.requests {
				t.Errorf("sent %d requests, want %d", len(*pops), tc.requests)
			}
		})
	}
}

// TestRequestPreAuthorizedCodeToken_UnchallengedError: a
// use_attestation_challenge error without a Challenge header isn't
// retried: there's nothing new to put in the PoP.
func TestRequestPreAuthorizedCodeToken_UnchallengedError(t *testing.T) {
	w, pops, _ := tokenServer(t, errorResponse("use_attestation_challenge", nil))
	if err := requestToken(w, t, &challengeSource{}); err == nil || len(*pops) != 1 {
		t.Errorf("err = %v after %d requests, want the error after one", err, len(*pops))
	}
}
