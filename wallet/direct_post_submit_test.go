package wallet_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// verifierReply starts a TLS response_uri that checks the submitted
// "response" form parameter and answers with status, contentType and
// body.
func verifierReply(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.PostFormValue("response") != "the-jwe" {
			http.Error(w, "unexpected request", http.StatusTeapot)
			return
		}
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSubmitDirectPostResponse(t *testing.T) {
	for name, tc := range map[string]struct {
		status      int
		contentType string
		body        string
		want        string // expected RedirectURI
		wantErr     string // substring; "" for success
	}{
		"redirect_uri":          {200, "application/json", `{"redirect_uri":"https://verifier.example/continue?response_code=abc"}`, "https://verifier.example/continue?response_code=abc", ""},
		"json with charset":     {200, "application/json; charset=utf-8", `{"redirect_uri":"https://verifier.example/cb"}`, "https://verifier.example/cb", ""},
		"no redirect_uri":       {200, "application/json", `{}`, "", ""},
		"not json":              {200, "text/plain", `ok`, "", ""},
		"http redirect_uri":     {200, "application/json", `{"redirect_uri":"http://verifier.example/cb"}`, "", "isn't an absolute https URL"},
		"relative redirect_uri": {200, "application/json", `{"redirect_uri":"/cb"}`, "", "isn't an absolute https URL"},
		"malformed json":        {200, "application/json", `{"redirect_uri":`, "", "parse reply"},
		"oversized reply":       {200, "application/json", `{"x":"` + strings.Repeat("a", 70<<10) + `"}`, "", "exceeds"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := verifierReply(t, tc.status, tc.contentType, tc.body)
			got, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL, "the-jwe")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.RedirectURI != tc.want {
				t.Fatalf("SubmitDirectPostResponse = %+v, %v; want redirect %q", got, err, tc.want)
			}
		})
	}
}

func TestSubmitDirectPostResponse_Rejected(t *testing.T) {
	srv := verifierReply(t, http.StatusBadRequest, "application/json", `{"error":"invalid_request","error_description":"nonce mismatch"}`)
	_, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL, "the-jwe")
	var rejected *wallet.DirectPostRejectedError
	if !errors.As(err, &rejected) || rejected.StatusCode != http.StatusBadRequest || rejected.Code != "invalid_request" || rejected.Description != "nonce mismatch" {
		t.Fatalf("error = %#v, want a DirectPostRejectedError carrying the verifier's error", err)
	}
}

func TestSubmitDirectPostResponse_RejectedTextSanitized(t *testing.T) {
	srv := verifierReply(t, http.StatusBadRequest, "application/json",
		`{"error":"invalid_request\nFAKE LOG LINE","error_description":"`+strings.Repeat("x", 1000)+`"}`)
	_, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL, "the-jwe")
	var rejected *wallet.DirectPostRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %#v, want a DirectPostRejectedError", err)
	}
	if rejected.Code != "invalid_requestFAKE LOG LINE" {
		t.Errorf("Code = %q, want the control character dropped", rejected.Code)
	}
	if n := len([]rune(rejected.Description)); n != 257 || !strings.HasSuffix(rejected.Description, "…") {
		t.Errorf("Description is %d runes, want 256 plus an ellipsis", n)
	}
}

// TestSubmitDirectPostResponse_DoesNotFollowRedirects checks a redirect
// from response_uri is refused without the response being resent to its
// target — here plain http, whose reply could name any redirect_uri.
func TestSubmitDirectPostResponse_DoesNotFollowRedirects(t *testing.T) {
	var targetHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit.Store(true)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://attacker.example/phish"}`))
	}))
	t.Cleanup(target.Close)
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect, http.StatusFound} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+"/response", status)
		}))
		t.Cleanup(srv.Close)
		_, err := wallet.SubmitDirectPostResponse(context.Background(), srv.Client(), srv.URL, "the-jwe")
		if err == nil || !strings.Contains(err.Error(), "redirect") {
			t.Errorf("status %d: error = %v, want a refused redirect", status, err)
		}
	}
	if targetHit.Load() {
		t.Error("the response was resent to the redirect target")
	}
}

// redirectingClient stands in for an HTTPClient other than *http.Client
// that followed a redirect: its reply comes from another URL.
type redirectingClient struct{ from string }

func (c redirectingClient) Do(req *http.Request) (*http.Response, error) {
	final, err := http.NewRequest(http.MethodGet, c.from, nil)
	if err != nil {
		return nil, err
	}
	return &http.Response{
		StatusCode: http.StatusOK, Request: final,
		Header: http.Header{"Content-Type": {"application/json"}},
		Body:   io.NopCloser(strings.NewReader(`{"redirect_uri":"https://attacker.example/phish"}`)),
	}, nil
}

func TestSubmitDirectPostResponse_RefusesReplyFromElsewhere(t *testing.T) {
	_, err := wallet.SubmitDirectPostResponse(context.Background(), redirectingClient{from: "http://elsewhere.example/r"}, "https://verifier.example/response", "the-jwe")
	if err == nil || !strings.Contains(err.Error(), "not response_uri") {
		t.Fatalf("error = %v, want the reply from elsewhere refused", err)
	}
}
