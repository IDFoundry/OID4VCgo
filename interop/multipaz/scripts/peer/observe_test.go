package main

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDescribeJWKs(t *testing.T) {
	for raw, want := range map[string]string{
		`{"keys":[{"kty":"EC","alg":"ECDH-ES","kid":"k1"}]}`:   "alg=ECDH-ES,kid=present",
		`{"keys":[{"kty":"EC"},{"kty":"EC","alg":"ECDH-ES"}]}`: "alg=-,kid=-;alg=ECDH-ES,kid=-",
		`{"keys":[]}`: "empty",
		`[]`:          "unreadable",
	} {
		if got := describeJWKs([]byte(raw)); got != want {
			t.Errorf("describeJWKs(%s) = %q, want %q", raw, got, want)
		}
	}
}

func TestRecorder(t *testing.T) {
	requestObject := "e30." + base64.RawURLEncoding.EncodeToString([]byte(`{"client_metadata":{"jwks":{"keys":[{"kty":"EC","kid":"a"}]}}}`)) + ".c2ln"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/request":
			w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
			_, _ = io.WriteString(w, requestObject)
		case "/.well-known/openid-credential-issuer":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"credential_issuer":"x"}`)
		case "/token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"t","token_type":"Bearer"}`)
		}
	}))
	defer srv.Close()
	rec := newRecorder(http.DefaultTransport)
	client := &http.Client{Transport: rec}
	for _, r := range []struct{ method, path string }{{"GET", "/request"}, {"GET", "/.well-known/openid-credential-issuer"}, {"POST", "/token"}} {
		req, _ := http.NewRequest(r.method, srv.URL+r.path, nil)
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		if body, _ := io.ReadAll(res.Body); len(body) == 0 {
			t.Errorf("%s: the body wasn't passed on", r.path)
		}
		_ = res.Body.Close()
	}
	got := rec.snapshot()
	want := map[string]string{"verifier_jwks": "alg=-,kid=present", "request_enc_jwks": "none", "token_type": "Bearer"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if got := dcapiVerifierJWKs(`{"request":"` + requestObject + `"}`); got != "alg=-,kid=present" {
		t.Errorf("dcapiVerifierJWKs = %q", got)
	}
}
