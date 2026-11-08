package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/verifier"
)

const testOrigin = "https://verifier.example.com"

// newRoutedServer builds a server from cfg as main does, with its
// routes.
func newRoutedServer(t *testing.T, cfg Config) (*server, http.Handler) {
	t.Helper()
	s, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s, s.routes()
}

func TestNewServer(t *testing.T) {
	mdoc := mdocTestConfig(t)
	mdoc.StatusListTrustAnchorsPEM = mdoc.MdocTrustAnchorPEM
	s, err := newServer(mdoc)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if s.mdocIssuerKeys == nil || s.status == nil || s.issuerKeys == nil {
		t.Fatalf("newServer = %+v, want mdoc issuer keys, a status policy and the configured SD-JWT VC issuer", s)
	}
	for name, mutate := range map[string]func(*Config){
		"client_certificate_pem":              func(c *Config) { c.ClientCertificatePEM = "" },
		"credential_issuer_trust_anchors_pem": func(c *Config) { c.CredentialIssuerTrustAnchorsPEM = "not a certificate" },
		"status_list_trust_anchors_pem":       func(c *Config) { c.StatusListTrustAnchorsPEM = "not a certificate" },
		"base_url":                            func(c *Config) { c.BaseURL = "http://verifier.example.com" },
		"mdoc_trust_anchor_pem": func(c *Config) {
			c.CredentialFormat, c.MdocTrustAnchorPEM = "mso_mdoc", "not a certificate"
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := interopTestConfig(t)
			mutate(&cfg)
			if _, err := newServer(cfg); err == nil {
				t.Fatalf("newServer = nil error, want one for %s", name)
			}
		})
	}
}

func interopTestConfig(t *testing.T) Config {
	t.Helper()
	caPEM, _ := testPEMCertAndKey(t)
	cfg := baseTestConfig(t)
	cfg.CredentialIssuerJWK = nil
	cfg.CredentialIssuerTrustAnchorsPEM = caPEM
	cfg.StatusListTrustAnchorsPEM = caPEM
	cfg.StatusListTLSTrustAnchorsPEM = caPEM
	cfg.StatusListAllowLoopback = true
	cfg.DCAPIOrigins = []string{testOrigin}
	return cfg
}

func TestLoadConfig_InteropRoundTrips(t *testing.T) {
	cfg := interopTestConfig(t)
	got, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if got.CredentialIssuerTrustAnchorsPEM == "" || !got.StatusListAllowLoopback || len(got.DCAPIOrigins) != 1 {
		t.Fatalf("loadConfig round-trip mismatch: got %+v", got)
	}
}

func TestLoadConfig_IssuerTrustIsExactlyOne(t *testing.T) {
	both := interopTestConfig(t)
	both.CredentialIssuerJWK = baseTestConfig(t).CredentialIssuerJWK
	neither := interopTestConfig(t)
	neither.CredentialIssuerTrustAnchorsPEM = ""
	for name, cfg := range map[string]Config{"both": both, "neither": neither} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatal("loadConfig = nil error, want one for credential_issuer_jwk with credential_issuer_trust_anchors_pem")
			}
		})
	}
}

func TestLoadConfig_MdocNeedsNoCredentialIssuerJWK(t *testing.T) {
	cfg := mdocTestConfig(t)
	cfg.CredentialIssuerJWK = nil
	if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
}

func TestLoadConfig_StatusOptionsNeedTrustAnchors(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"status_list_tls_trust_anchors_pem": func(c *Config) { c.StatusListAllowLoopback = false },
		"status_list_allow_loopback":        func(c *Config) { c.StatusListTLSTrustAnchorsPEM = "" },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := interopTestConfig(t)
			cfg.StatusListTrustAnchorsPEM = ""
			mutate(&cfg)
			if _, err := loadConfig(conformancecert.WriteJSONConfig(t, cfg)); err == nil {
				t.Fatalf("loadConfig = nil error, want one for %s without status_list_trust_anchors_pem", name)
			}
		})
	}
}

func TestConfig_SDJWTVCIssuerKeys(t *testing.T) {
	anchors, err := interopTestConfig(t).sdJWTVCIssuerKeys()
	if err != nil {
		t.Fatalf("sdJWTVCIssuerKeys: %v", err)
	}
	if _, ok := anchors.(verifier.X5CIssuerKeyResolver); !ok {
		t.Fatalf("sdJWTVCIssuerKeys = %T, want verifier.X5CIssuerKeyResolver", anchors)
	}
	static, err := baseTestConfig(t).sdJWTVCIssuerKeys()
	if err != nil {
		t.Fatalf("sdJWTVCIssuerKeys: %v", err)
	}
	if _, ok := static.(staticIssuerKeyResolver); !ok {
		t.Fatalf("sdJWTVCIssuerKeys = %T, want staticIssuerKeyResolver", static)
	}
	none := mdocTestConfig(t)
	none.CredentialIssuerJWK = nil
	if keys, err := none.sdJWTVCIssuerKeys(); err != nil || keys != nil {
		t.Fatalf("sdJWTVCIssuerKeys = %v, %v; want nil, nil", keys, err)
	}
	bad := interopTestConfig(t)
	bad.CredentialIssuerTrustAnchorsPEM = "not a certificate"
	if _, err := bad.sdJWTVCIssuerKeys(); err == nil {
		t.Fatal("sdJWTVCIssuerKeys = nil error, want one for unparseable anchors")
	}
}

func TestConfig_StatusPolicy(t *testing.T) {
	if p, err := baseTestConfig(t).statusPolicy(); err != nil || p != nil {
		t.Fatalf("statusPolicy = %v, %v; want nil, nil without status_list_trust_anchors_pem", p, err)
	}
	p, err := interopTestConfig(t).statusPolicy()
	if err != nil {
		t.Fatalf("statusPolicy: %v", err)
	}
	if !p.RequireReference || p.Checker.Roots == nil || !p.Checker.Fetcher.AllowLoopback || p.Checker.Fetcher.HTTP == nil {
		t.Fatalf("statusPolicy = %+v, want RequireReference, Roots, AllowLoopback and an HTTP client", p)
	}
	for _, field := range []string{"status_list_trust_anchors_pem", "status_list_tls_trust_anchors_pem"} {
		cfg := interopTestConfig(t)
		if field == "status_list_trust_anchors_pem" {
			cfg.StatusListTrustAnchorsPEM = "not a certificate"
		} else {
			cfg.StatusListTLSTrustAnchorsPEM = "not a certificate"
		}
		if _, err := cfg.statusPolicy(); err == nil || !strings.Contains(err.Error(), field) {
			t.Fatalf("statusPolicy error = %v, want one naming %s", err, field)
		}
	}
}

func TestHandleAuthorize_RequestURIMethodParameter(t *testing.T) {
	_, mux := newRoutedServer(t, interopTestConfig(t))
	for param, want := range map[string]string{"": "post", "post": "post", "get": "get", "none": ""} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?request_uri_method="+param, nil))
		if rec.Code != http.StatusFound {
			t.Fatalf("request_uri_method=%q: GET /authorize = %d", param, rec.Code)
		}
		u, err := url.Parse(rec.Header().Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		got, present := u.Query()["request_uri_method"]
		if want == "" {
			if present {
				t.Fatalf("request_uri_method=none: the launch has request_uri_method %v, want none", got)
			}
		} else if len(got) != 1 || got[0] != want {
			t.Fatalf("request_uri_method=%q: the launch has %v, want %q", param, got, want)
		}
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?request_uri_method=put", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("request_uri_method=put: GET /authorize = %d, want 400", rec.Code)
	}
}

// startBuiltSession starts a session and fetches its Request Object
// with a POST carrying wallet_metadata, returning the session.
func startBuiltSession(t *testing.T, s *server, mux http.Handler) *session {
	t.Helper()
	id, _ := startSession(t, mux)
	form := url.Values{"wallet_nonce": {"n-1"}, "wallet_metadata": {`{"vp_formats_supported":{}}`}}
	req := httptest.NewRequest(http.MethodPost, "/request/"+id, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/oauth-authz-req+jwt")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /request/%s = %d", id, rec.Code)
	}
	sess, ok := s.sessions.get(id)
	if !ok {
		t.Fatalf("session %s not found", id)
	}
	return sess
}

func TestHandleRequestObject_RecordsTheFetch(t *testing.T) {
	s, mux := newRoutedServer(t, interopTestConfig(t))
	sess := startBuiltSession(t, s, mux)
	want := requestFetch{
		Method: http.MethodPost, Accept: "application/oauth-authz-req+jwt", ContentType: "application/x-www-form-urlencoded",
		WalletNonce: "n-1", WalletMetadata: `{"vp_formats_supported":{}}`,
	}
	if sess.fetch != want {
		t.Fatalf("fetch = %+v, want %+v", sess.fetch, want)
	}
}

// encryptTo encrypts payload to sess's response encryption key, as a
// Wallet's direct_post.jwt or dc_api.jwt response.
func encryptTo(t *testing.T, sess *session, payload string) string {
	t.Helper()
	compact, err := jwe.Encrypt(&sess.decryptionKey.PublicKey, jwe.A128GCM, []byte(payload), jwe.EncryptOptions{})
	if err != nil {
		t.Fatalf("jwe.Encrypt: %v", err)
	}
	return compact
}

func postResponse(mux http.Handler, responseJWE string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/response", strings.NewReader(url.Values{"response": {responseJWE}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func get(mux http.Handler, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

func decodeOutcome(t *testing.T, rec *httptest.ResponseRecorder) outcome {
	t.Helper()
	var o outcome
	if err := json.Unmarshal(rec.Body.Bytes(), &o); err != nil {
		t.Fatalf("decode outcome %q: %v", rec.Body.String(), err)
	}
	return o
}

func TestHandleResponse_RedeemsTheResponseCodeOnceAndRefusesAReplay(t *testing.T) {
	s, mux := newRoutedServer(t, interopTestConfig(t))
	sess := startBuiltSession(t, s, mux)
	response := encryptTo(t, sess, `{"error":"access_denied"}`)

	rec := postResponse(mux, response)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /response = %d: %s", rec.Code, rec.Body)
	}
	var body struct {
		RedirectURI string `json:"redirect_uri"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(body.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("response_code")
	if redirect.Path != "/result/"+sess.id || code == "" {
		t.Fatalf("redirect_uri = %q, want /result/%s with a response_code", body.RedirectURI, sess.id)
	}
	if rec := get(mux, redirect.Path); rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d", redirect.Path, rec.Code)
	}

	redeem := "/result/" + sess.id + "/redeem?response_code="
	if rec := get(mux, redeem+"wrong"); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem with the wrong code = %d, want 403", rec.Code)
	}
	rec = get(mux, redeem+url.QueryEscape(code))
	if rec.Code != http.StatusOK {
		t.Fatalf("redeem = %d, want 200", rec.Code)
	}
	o := decodeOutcome(t, rec)
	if o.Status != "failed" || !strings.Contains(o.Error, "access_denied") || o.RequestURIFetch == nil || o.RequestURIFetch.WalletNonce != "n-1" {
		t.Fatalf("outcome = %+v, want failed with access_denied and the fetch", o)
	}
	if rec := get(mux, redeem+url.QueryEscape(code)); rec.Code != http.StatusForbidden {
		t.Fatalf("redeem again = %d, want 403", rec.Code)
	}
	if rec := get(mux, "/result/unknown/redeem?response_code=x"); rec.Code != http.StatusNotFound {
		t.Fatalf("redeem of an unknown session = %d, want 404", rec.Code)
	}

	if rec := postResponse(mux, response); rec.Code != http.StatusBadRequest {
		t.Fatalf("the replayed response = %d, want 400", rec.Code)
	}
}

func TestHandleResponse_VerifiesAVPToken(t *testing.T) {
	s, mux := newRoutedServer(t, interopTestConfig(t))
	sess := startBuiltSession(t, s, mux)
	if rec := postResponse(mux, encryptTo(t, sess, `{"vp_token":{"cred1":["not-an-sd-jwt"]}}`)); rec.Code != http.StatusOK {
		t.Fatalf("POST /response = %d", rec.Code)
	}
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if !sess.done || sess.failErr == nil || sess.responseCode == "" {
		t.Fatalf("session = done %v, failErr %v, response code %q; want done, refused, with a code", sess.done, sess.failErr, sess.responseCode)
	}
}

func TestHandleResponse_RefusesASecondAnswerToAnAnsweredSession(t *testing.T) {
	s, mux := newRoutedServer(t, interopTestConfig(t))
	sess := startBuiltSession(t, s, mux)
	sess.mu.Lock()
	sess.done = true
	sess.mu.Unlock()
	// pendingDecryptionKeys no longer offers it.
	if rec := postResponse(mux, encryptTo(t, sess, `{"error":"access_denied"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /response = %d, want 400", rec.Code)
	}
}

func TestOutcomeOf(t *testing.T) {
	pending := outcomeOf(&session{})
	if pending.Status != "pending" || pending.RequestURIFetch == nil {
		t.Fatalf("outcomeOf(pending) = %+v", pending)
	}
	verified := outcomeOf(&session{done: true, result: []verifier.VerifiedCredential{
		{CredentialQueryID: "cred1", Claims: map[string]any{"given_name": "Jean"}},
	}})
	if verified.Status != "verified" || verified.Credentials["cred1"]["given_name"] != "Jean" {
		t.Fatalf("outcomeOf(verified) = %+v", verified)
	}
	failed := outcomeOf(&session{done: true, dcapi: true, failErr: errors.New("refused")})
	if failed.Status != "failed" || failed.Error != "refused" || failed.RequestURIFetch != nil {
		t.Fatalf("outcomeOf(failed, DC API) = %+v", failed)
	}
}

func dcAPIBegin(t *testing.T, mux http.Handler, origin string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/dcapi/request?origin="+url.QueryEscape(origin), nil))
	return rec
}

func dcAPIAnswer(mux http.Handler, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/dcapi/response/"+id, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestDCAPI_DisabledWithoutOrigins(t *testing.T) {
	cfg := interopTestConfig(t)
	cfg.DCAPIOrigins = nil
	_, mux := newRoutedServer(t, cfg)
	if rec := dcAPIBegin(t, mux, testOrigin); rec.Code != http.StatusNotFound {
		t.Fatalf("POST /dcapi/request = %d, want 404", rec.Code)
	}
}

func TestDCAPI_RefusesAnotherOrigin(t *testing.T) {
	_, mux := newRoutedServer(t, interopTestConfig(t))
	if rec := dcAPIBegin(t, mux, "https://attacker.example"); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /dcapi/request = %d, want 400", rec.Code)
	}
}

func TestDCAPI_RequestAndAnswers(t *testing.T) {
	s, mux := newRoutedServer(t, interopTestConfig(t))
	begin := func() (*session, dcAPIRequest) {
		rec := dcAPIBegin(t, mux, testOrigin)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST /dcapi/request = %d: %s", rec.Code, rec.Body)
		}
		var req dcAPIRequest
		if err := json.Unmarshal(rec.Body.Bytes(), &req); err != nil {
			t.Fatal(err)
		}
		sess, ok := s.sessions.get(req.ID)
		if !ok {
			t.Fatalf("session %s not found", req.ID)
		}
		return sess, req
	}

	sess, req := begin()
	if req.Protocol != "openid4vp-v1-signed" {
		t.Fatalf("protocol = %q", req.Protocol)
	}
	claims := decodeRequestObjectPayload(t, req.Data.Request)
	if claims["response_mode"] != "dc_api.jwt" || claims["expected_origins"].([]any)[0] != testOrigin {
		t.Fatalf("request = %v, want dc_api.jwt for %s", claims, testOrigin)
	}
	// Neither its request_uri nor its response_uri serves it.
	if rec := get(mux, "/request/"+req.ID); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /request/%s = %d, want 404", req.ID, rec.Code)
	}
	if rec := postResponse(mux, encryptTo(t, sess, `{"error":"access_denied"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /response for a DC API session = %d, want 400", rec.Code)
	}

	rec := dcAPIAnswer(mux, req.ID, `{"response":"`+encryptTo(t, sess, `{"vp_token":{"cred1":["not-an-sd-jwt"]}}`)+`"}`)
	if o := decodeOutcome(t, rec); rec.Code != http.StatusOK || o.Status != "failed" {
		t.Fatalf("an unverifiable answer = %d %+v, want 200 failed", rec.Code, o)
	}
	if rec := dcAPIAnswer(mux, req.ID, `{"error":"access_denied"}`); rec.Code != http.StatusConflict {
		t.Fatalf("a second answer = %d, want 409", rec.Code)
	}

	for body, want := range map[string]string{
		`{"error":"access_denied"}`:    "access_denied",
		`{"response":"not-a-jwe"}`:     "decode header",
		`{}`:                           `neither "response" nor "error"`,
		`{"response":"` + "x" + `", "`: "",
	} {
		_, req := begin()
		rec := dcAPIAnswer(mux, req.ID, body)
		if want == "" {
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("answer %s = %d, want 400", body, rec.Code)
			}
			continue
		}
		if o := decodeOutcome(t, rec); o.Status != "failed" || !strings.Contains(o.Error, want) {
			t.Fatalf("answer %s = %+v, want failed with %q", body, o, want)
		}
	}

	if rec := dcAPIAnswer(mux, "unknown", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("an answer for an unknown session = %d, want 404", rec.Code)
	}
	if rec := dcAPIAnswer(mux, req.ID, strings.Repeat("x", maxDCAPIResponseBytes+1)); rec.Code != http.StatusBadRequest {
		t.Fatalf("an oversized answer = %d, want 400", rec.Code)
	}
}

func TestSessionStore_PendingDecryptionKeysExcludesDCAPISessions(t *testing.T) {
	s := newSessionStore()
	s.put(&session{id: "dcapi", createdAt: time.Now(), built: true, dcapi: true})
	if got := s.pendingDecryptionKeys(); len(got) != 0 {
		t.Fatalf("pendingDecryptionKeys = %+v, want none: a DC API answer never comes to the response_uri", got)
	}
}
