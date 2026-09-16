package main

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwe"
	"github.com/idfoundry/oid4vcigo/verifier"
)

func newTestServer(t *testing.T) *server {
	t.Helper()
	cfg := baseTestConfig(t)
	clientCert, clientKey, err := cfg.clientCertificateAndKey()
	if err != nil {
		t.Fatalf("clientCertificateAndKey: %v", err)
	}
	issuerKeys, err := newStaticIssuerKeyResolver(cfg.CredentialIssuerJWK)
	if err != nil {
		t.Fatalf("newStaticIssuerKeyResolver: %v", err)
	}
	responseURI, err := fapi.ParseEndpointURL(cfg.BaseURL + "/response")
	if err != nil {
		t.Fatalf("ParseEndpointURL: %v", err)
	}
	v, err := verifier.New(verifier.Config{
		ClientCertificate:  clientCert,
		ResponseURI:        responseURI,
		SigningAlg:         jose.ES256,
		EncValuesSupported: []jwe.Enc{jwe.A128GCM, jwe.A256GCM},
		VPFormatsSupported: map[string]any{"dc+sd-jwt": map[string]any{"sd-jwt_alg_values": []string{"ES256"}}},
	}, verifier.Dependencies{Signer: clientKey, Random: rand.Reader})
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return &server{cfg: cfg, v: v, sessions: newSessionStore(), issuerKeys: issuerKeys}
}

// newTestMux wires the same routes main.go registers for /authorize
// and /request/{id} — GET and POST alike — against a fresh in-memory
// server, so these tests exercise real mux routing rather than calling
// handler methods directly.
func newTestMux(t *testing.T) (*server, http.Handler) {
	t.Helper()
	s := newTestServer(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /authorize", s.handleAuthorize)
	mux.HandleFunc("GET /request/{id}", s.handleRequestObject)
	mux.HandleFunc("POST /request/{id}", s.handleRequestObject)
	return s, mux
}

// startSession drives handleAuthorize and returns the session id and
// the full deep-link query, parsed straight out of the
// "openid4vp://" redirect handleAuthorize issues.
func startSession(t *testing.T, mux http.Handler) (id string, deepLink url.Values) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("GET /authorize = %d, want %d", rec.Code, http.StatusFound)
	}
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect Location %q: %v", loc, err)
	}
	deepLink = u.Query()
	requestURI := deepLink.Get("request_uri")
	if requestURI == "" {
		t.Fatalf("deep link %q has no request_uri", loc)
	}
	id = strings.TrimPrefix(requestURI, "https://verifier.example.com/request/")
	return id, deepLink
}

func TestHandleAuthorize_AdvertisesRequestURIMethodPost(t *testing.T) {
	_, mux := newTestMux(t)
	_, deepLink := startSession(t, mux)
	if got := deepLink.Get("request_uri_method"); got != "post" {
		t.Fatalf("request_uri_method = %q, want %q", got, "post")
	}
	if deepLink.Get("client_id") == "" {
		t.Fatalf("deep link has no client_id")
	}
}

func decodeRequestObjectPayload(t *testing.T, compact string) map[string]any {
	t.Helper()
	_, payload, err := jose.DecodeUnverified(compact)
	if err != nil {
		t.Fatalf("DecodeUnverified: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func TestHandleRequestObject_GETLeavesWalletNonceClaimAbsent(t *testing.T) {
	_, mux := newTestMux(t)
	id, _ := startSession(t, mux)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/request/"+id, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /request/%s = %d, want 200", id, rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/oauth-authz-req+jwt" {
		t.Fatalf("Content-Type = %q, want application/oauth-authz-req+jwt", ct)
	}
	claims := decodeRequestObjectPayload(t, rec.Body.String())
	if _, present := claims["wallet_nonce"]; present {
		t.Fatalf("wallet_nonce claim present = %v, want absent for a plain GET fetch", claims["wallet_nonce"])
	}
}

func TestHandleRequestObject_POSTEmbedsWalletNonceClaim(t *testing.T) {
	_, mux := newTestMux(t)
	id, _ := startSession(t, mux)

	form := url.Values{"wallet_nonce": {"test-nonce-value"}}
	req := httptest.NewRequest(http.MethodPost, "/request/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /request/%s = %d, want 200", id, rec.Code)
	}
	claims := decodeRequestObjectPayload(t, rec.Body.String())
	if got := claims["wallet_nonce"]; got != "test-nonce-value" {
		t.Fatalf("wallet_nonce claim = %v, want %q", got, "test-nonce-value")
	}
}

// TestHandleRequestObject_BuildsExactlyOnce proves the "built once"
// contract session.ensureBuilt documents: a later POST's own
// wallet_nonce must not retroactively change an already-served Request
// Object, since its nonce/response-encryption key have to stay stable
// for handleResponse's own later matching/decryption.
func TestHandleRequestObject_BuildsExactlyOnce(t *testing.T) {
	_, mux := newTestMux(t)
	id, _ := startSession(t, mux)

	rec1 := httptest.NewRecorder()
	mux.ServeHTTP(rec1, httptest.NewRequest(http.MethodGet, "/request/"+id, nil))

	form := url.Values{"wallet_nonce": {"should-not-appear"}}
	req := httptest.NewRequest(http.MethodPost, "/request/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, req)

	if rec1.Body.String() != rec2.Body.String() {
		t.Fatalf("a later POST fetch changed the already-built Request Object; want the first-built object replayed unchanged")
	}
}

func TestHandleRequestObject_UnknownSession404s(t *testing.T) {
	_, mux := newTestMux(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/request/unknown-id", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /request/unknown-id = %d, want 404", rec.Code)
	}
}
