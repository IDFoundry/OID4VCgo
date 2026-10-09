package wallet_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"
)

func testChallengeEndpoint(t *testing.T) fapi.URL {
	t.Helper()
	u, err := fapi.ParseEndpointURL("http://localhost/challenge", fapi.AllowLoopbackHTTP())
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	return u
}

func TestRequestAttestationChallenge(t *testing.T) {
	w := newTestWallet(t, func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", req.Method)
		}
		return jsonResponse([]byte(`{"attestation_challenge":"AYjcyMzY3ZDhiNmJkNTZ"}`)), nil
	})
	got, err := w.RequestAttestationChallenge(context.Background(), testChallengeEndpoint(t))
	if err != nil || got != "AYjcyMzY3ZDhiNmJkNTZ" {
		t.Errorf("RequestAttestationChallenge = %q, %v", got, err)
	}
}

func TestRequestAttestationChallenge_Refuses(t *testing.T) {
	for name, body := range map[string]string{
		"no challenge":       `{}`,
		"an empty challenge": `{"attestation_challenge":""}`,
		"a long challenge":   `{"attestation_challenge":"` + strings.Repeat("a", 1025) + `"}`,
		"malformed JSON":     `{"attestation_challenge":`,
	} {
		w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
			return jsonResponse([]byte(body)), nil
		})
		if _, err := w.RequestAttestationChallenge(context.Background(), testChallengeEndpoint(t)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
