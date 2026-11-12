package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The walletflow engine's key store holds the configured holder key
// alone, and creates none.
func TestFixtureKeys(t *testing.T) {
	ctx := context.Background()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := fixtureKeys{key: fixtureKey{key}}
	if _, err := keys.NewKey(ctx, walletflow.KeyPurposeHolder); err == nil {
		t.Error("NewKey made a key")
	}
	if k, err := keys.Key(ctx, fixtureKeyID); err != nil || k.ID() != fixtureKeyID {
		t.Errorf("Key(%q) = %v, %v", fixtureKeyID, k, err)
	}
	if _, err := keys.Key(ctx, "other"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Key(other) = %v, want ErrNotFound", err)
	}
	if err := keys.DeleteKey(ctx, fixtureKeyID); err != nil {
		t.Errorf("DeleteKey: %v", err)
	}
}

// An mdoc fixture is stored without a vct.
func TestNewFlow_Mdoc(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{CredentialFormat: mdoc.CredentialFormat, VCT: "ignored"}
	cred := wallet.HeldCredential{Format: mdoc.CredentialFormat, Credential: "AA", HolderKey: key, MdocDocType: "org.iso.18013.5.1.mDL"}
	if _, err := newFlow(cfg, cred, wallet.NoVerifierTrust{}, unverifiedClient(t)); err != nil {
		t.Fatal(err)
	}
}

// walletflowServer is a walletflow engine holding setupWalletUnderTest's
// fixture, trusting any Verifier.
func walletflowServer(t *testing.T) *server {
	t.Helper()
	srv, _ := setupWalletUnderTest(t)
	srv.trust, srv.http = wallet.NoVerifierTrust{}, unverifiedClient(t)
	flow, err := newFlow(Config{VCT: "urn:eudi:pid:1"}, srv.cred, srv.trust, srv.http)
	if err != nil {
		t.Fatal(err)
	}
	srv.flow = flow
	return srv
}

// pidQuery asks for the fixture setupWalletUnderTest issues.
var pidQuery = map[string]any{"credentials": []any{map[string]any{
	"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
	"claims": []any{map[string]any{"path": []any{"given_name"}}},
}}}

func authorizeWalletflow(t *testing.T, srv *server, clientID, requestURI string) *httptest.ResponseRecorder {
	t.Helper()
	target := "/authorize?" + url.Values{"client_id": {clientID}, "request_uri": {requestURI}}.Encode()
	rec := httptest.NewRecorder()
	srv.handleAuthorizeWalletflow(rec, httptest.NewRequest(http.MethodGet, target, nil))
	return rec
}

// A request walletflow can't fetch is answered 400, sending nothing.
func TestHandleAuthorizeWalletflow_FetchFails(t *testing.T) {
	srv := walletflowServer(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such request", http.StatusBadRequest)
	}))
	t.Cleanup(ts.Close)
	rec := authorizeWalletflow(t, srv, "x509_hash:AAAA", ts.URL)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

// responseCapture serves a response_uri, recording each POST.
func responseCapture(t *testing.T) (responseURI string, posts *int) {
	t.Helper()
	posts = new(int)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			*posts++
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(ts.Close)
	return ts.URL, posts
}

// An authentic request walletflow refuses (redirect_uri beside
// direct_post) is answered with an error response, and reported as
// Rejected.
func TestHandleAuthorizeWalletflow_Refused(t *testing.T) {
	srv := walletflowServer(t)
	responseURI, posts := responseCapture(t)
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{
		"redirect_uri": "https://wallet.example.com/callback", "response_uri": responseURI,
	})
	rec := authorizeWalletflow(t, srv, clientID, serveRequestObject(t, compact))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Rejected") || !strings.Contains(rec.Body.String(), "Sent error response: invalid_request") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if *posts != 1 {
		t.Errorf("response_uri got %d POSTs, want the error response", *posts)
	}
}

// A request for a credential the wallet doesn't hold is declined.
func TestHandleAuthorizeWalletflow_Declined(t *testing.T) {
	srv := walletflowServer(t)
	responseURI, posts := responseCapture(t)
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{
		"response_uri": responseURI,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "mdl", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": "org.iso.18013.5.1.mDL"},
		}}},
	})
	rec := authorizeWalletflow(t, srv, clientID, serveRequestObject(t, compact))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Declined") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if *posts != 1 {
		t.Errorf("response_uri got %d POSTs, want the declination", *posts)
	}
}

// A declination that can't be delivered is answered 502.
func TestHandleAuthorizeWalletflow_DeclineFails(t *testing.T) {
	srv := walletflowServer(t)
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	responseURI := dead.URL
	dead.Close()
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{
		"response_uri": responseURI,
		"dcql_query": map[string]any{"credentials": []any{map[string]any{
			"id": "mdl", "format": "mso_mdoc", "meta": map[string]any{"doctype_value": "org.iso.18013.5.1.mDL"},
		}}},
	})
	rec := authorizeWalletflow(t, srv, clientID, serveRequestObject(t, compact))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

// A presentation the Verifier takes without a redirect_uri says so.
func TestHandleAuthorizeWalletflow_NoRedirect(t *testing.T) {
	srv := walletflowServer(t)
	responseURI, posts := responseCapture(t)
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{"response_uri": responseURI, "dcql_query": pidQuery})
	rec := authorizeWalletflow(t, srv, clientID, serveRequestObject(t, compact))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Presented") || !strings.Contains(rec.Body.String(), "No redirect_uri was returned.") {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if *posts != 1 {
		t.Errorf("response_uri got %d POSTs, want the presentation", *posts)
	}
}

// A presentation the Verifier refuses at its response_uri is answered
// 502.
func TestHandleAuthorizeWalletflow_RespondFails(t *testing.T) {
	srv := walletflowServer(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "refused", http.StatusBadRequest)
	}))
	t.Cleanup(ts.Close)
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{"response_uri": ts.URL, "dcql_query": pidQuery})
	rec := authorizeWalletflow(t, srv, clientID, serveRequestObject(t, compact))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
}

// A refused fetch, by GET or by POST, reports what the Verifier
// answers, at most maxRefusalBytes of it.
func TestFetchAndVerifyRequestObject_ReportsTheRefusal(t *testing.T) {
	long := strings.Repeat("x", 2*maxRefusalBytes)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no such outstanding request "+long, http.StatusBadRequest)
	}))
	t.Cleanup(ts.Close)
	for _, post := range []bool{false, true} {
		_, err := fetchRequestObject(t, ts.URL, "x509_hash:AAAA", post, wallet.NoVerifierTrust{})
		if err == nil {
			t.Fatalf("post %v: a refused fetch succeeded", post)
		}
		msg := err.Error()
		if !strings.Contains(msg, "(the verifier answers: status 400: no such outstanding request") {
			t.Errorf("post %v: %v", post, err)
		}
		if strings.Count(msg, "x") > maxRefusalBytes {
			t.Errorf("post %v: the refusal was reported past %d bytes", post, maxRefusalBytes)
		}
	}
}

// refusalBody reports a Verifier it can't reach, or a request_uri it
// can't request, by the error.
func TestRefusalBody_Errors(t *testing.T) {
	s := &server{http: unverifiedClient(t)}
	dead := httptest.NewTLSServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	if got := s.refusalBody(context.Background(), deadURL); !strings.Contains(got, "connect") {
		t.Errorf("unreachable: %q", got)
	}
	if got := s.refusalBody(context.Background(), "://bad"); !strings.Contains(got, "missing protocol scheme") {
		t.Errorf("bad URL: %q", got)
	}
}

// A request_uri that doesn't parse isn't fetched.
func TestFetchAndVerifyRequestObject_BadURI(t *testing.T) {
	s := &server{trust: wallet.NoVerifierTrust{}, http: unverifiedClient(t)}
	if _, err := s.fetchAndVerifyRequestObject(context.Background(), wallet.AuthorizationRequestLink{RequestURI: "://bad", ClientID: "x509_hash:AAAA"}); err == nil {
		t.Fatal("a request_uri that doesn't parse was fetched")
	}
}

// parseCertificatesPEM skips other blocks, and refuses a certificate
// that doesn't parse.
func TestParseCertificatesPEM(t *testing.T) {
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(ts.Close)
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	other := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte{1}})
	certs, err := parseCertificatesPEM(string(other) + string(cert))
	if err != nil || len(certs) != 1 {
		t.Fatalf("parseCertificatesPEM = %d certificates, %v", len(certs), err)
	}
	bad := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})
	if _, err := parseCertificatesPEM(string(bad)); err == nil {
		t.Error("a malformed certificate was accepted")
	}
	if _, err := parseCertificatesPEM(string(other)); err == nil {
		t.Error("PEM without a certificate was accepted")
	}
	if !certs[0].Equal(ts.Certificate()) {
		t.Error("parseCertificatesPEM returned another certificate")
	}
}
