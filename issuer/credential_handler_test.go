package issuer_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// fakeTokens accepts any request, or none when err is set.
type fakeTokens struct {
	grant    issuer.Grant
	err      error
	endpoint *url.URL
}

func (f *fakeTokens) Verify(_ *http.Request, endpoint *url.URL) (issuer.Grant, error) {
	f.endpoint = endpoint
	return f.grant, f.err
}

func (f *fakeTokens) WriteError(w http.ResponseWriter, _ error) {
	w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
	w.WriteHeader(http.StatusUnauthorized)
}

type credentialHandlerRun struct {
	tokens   *fakeTokens
	prepared *issuer.Grant
	outcome  []bool
}

func newCredentialHandler(t *testing.T, f credentialEndpointFixture, prepareErr error) (http.Handler, *credentialHandlerRun) {
	t.Helper()
	run := &credentialHandlerRun{tokens: &fakeTokens{grant: issuer.Grant{
		Subject: "holder-1", DPoPNonce: "next-nonce",
		Authorized: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("test-client"), Scopes: []string{"identity_credential"}},
	}}}
	h, err := f.iss.CredentialHandler(issuer.CredentialHandlerConfig{
		URL: mustURL(t, testCredentialEndpoint), Tokens: run.tokens,
		Prepare: func(_ context.Context, grant issuer.Grant, req *issuer.CredentialRequest) (func(bool), error) {
			if prepareErr != nil {
				return nil, prepareErr
			}
			run.prepared = &grant
			req.SDJWTClaims = testSDJWTClaims()
			return func(issued bool) { run.outcome = append(run.outcome, issued) }, nil
		},
	})
	if err != nil {
		t.Fatalf("CredentialHandler: %v", err)
	}
	return h, run
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func postCredentialRequest(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/credential", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func sdjwtCredentialRequestBody(t *testing.T, f credentialEndpointFixture) string {
	t.Helper()
	proof := buildJWTProof(t, testP256Key(t), testIssuer, f.issueNonce(t))
	body, err := json.Marshal(map[string]any{
		"credential_configuration_id": testSDJWTConfigID,
		"proofs":                      map[string][]string{oid4vci.ProofTypeJWT: {proof}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestCredentialHandler_Issues(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	h, run := newCredentialHandler(t, f, nil)

	w := postCredentialRequest(t, h, sdjwtCredentialRequestBody(t, f))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := w.Header().Get("DPoP-Nonce"); got != "next-nonce" {
		t.Errorf("DPoP-Nonce = %q, want the grant's next nonce", got)
	}
	var resp oid4vci.CredentialResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Credentials) != 1 {
		t.Fatalf("response = %s (%v), want one credential", w.Body, err)
	}
	if run.tokens.endpoint.String() != testCredentialEndpoint {
		t.Errorf("token checked for %v, want the configured endpoint URL", run.tokens.endpoint)
	}
	if run.prepared == nil || run.prepared.Subject != "holder-1" {
		t.Errorf("Prepare got %+v, want the verified grant", run.prepared)
	}
	if len(run.outcome) != 1 || !run.outcome[0] {
		t.Errorf("done called with %v, want [true]", run.outcome)
	}
}

func TestCredentialHandler_Refusals(t *testing.T) {
	f := newCredentialEndpointFixture(t)

	t.Run("method", func(t *testing.T) {
		h, _ := newCredentialHandler(t, f, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/credential", nil))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodPost {
			t.Errorf("GET = %d (Allow %q), want 405 allowing POST", w.Code, w.Header().Get("Allow"))
		}
	})

	t.Run("access token", func(t *testing.T) {
		h, run := newCredentialHandler(t, f, nil)
		run.tokens.err = errors.New("expired")
		w := postCredentialRequest(t, h, "{}")
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("status = %d, want the token verifier's own 401", w.Code)
		}
		if run.prepared != nil {
			t.Error("Prepare ran for a request whose access token failed")
		}
	})

	t.Run("malformed request", func(t *testing.T) {
		h, run := newCredentialHandler(t, f, nil)
		w := postCredentialRequest(t, h, "[]")
		assertCredentialErrorResponse(t, w, http.StatusBadRequest, issuer.ErrorInvalidCredentialRequest)
		if run.prepared != nil {
			t.Error("Prepare ran for an unparsable request")
		}
	})

	t.Run("denied by Prepare", func(t *testing.T) {
		h, _ := newCredentialHandler(t, f, issuer.NewError(issuer.ErrorCredentialRequestDenied, "already issued"))
		w := postCredentialRequest(t, h, sdjwtCredentialRequestBody(t, f))
		assertCredentialErrorResponse(t, w, http.StatusBadRequest, issuer.ErrorCredentialRequestDenied)
	})

	t.Run("Prepare failure stays private", func(t *testing.T) {
		h, _ := newCredentialHandler(t, f, errors.New("database password is hunter2"))
		w := postCredentialRequest(t, h, sdjwtCredentialRequestBody(t, f))
		if w.Code != http.StatusInternalServerError || strings.Contains(w.Body.String(), "hunter2") {
			t.Errorf("status = %d, body %q: want a 500 that doesn't reveal the error", w.Code, w.Body)
		}
	})

	t.Run("issuing fails", func(t *testing.T) {
		h, run := newCredentialHandler(t, f, nil)
		w := postCredentialRequest(t, h, `{"credential_configuration_id":"`+testSDJWTConfigID+`"}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400 for a request without a proof", w.Code)
		}
		if len(run.outcome) != 1 || run.outcome[0] {
			t.Errorf("done called with %v, want [false]", run.outcome)
		}
	})
}

func assertCredentialErrorResponse(t *testing.T, w *httptest.ResponseRecorder, status int, code issuer.ErrorCode) {
	t.Helper()
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != status || body.Error != string(code) {
		t.Errorf("response = %d %s, want %d with error %q", w.Code, w.Body, status, code)
	}
}

func TestCredentialHandler_RequiresConfig(t *testing.T) {
	f := newCredentialEndpointFixture(t)
	prepare := func(context.Context, issuer.Grant, *issuer.CredentialRequest) (func(bool), error) { return nil, nil }
	for name, cfg := range map[string]issuer.CredentialHandlerConfig{
		"no URL":       {Tokens: &fakeTokens{}, Prepare: prepare},
		"relative URL": {URL: &url.URL{Path: "/credential"}, Tokens: &fakeTokens{}, Prepare: prepare},
		"no Tokens":    {URL: mustURL(t, testCredentialEndpoint), Prepare: prepare},
		"no Prepare":   {URL: mustURL(t, testCredentialEndpoint), Tokens: &fakeTokens{}},
	} {
		if _, err := f.iss.CredentialHandler(cfg); err == nil {
			t.Errorf("%s: CredentialHandler succeeded, want an error", name)
		}
	}
}
