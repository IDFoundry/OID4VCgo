package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// generateTestClientCert generates a fresh throwaway leaf certificate
// and computes its own x509_hash Client ID — the one piece
// buildSignedRequestObject and servePostRequestObject both need, the
// latter reusing the same cert/key across every request it signs
// rather than rotating identity mid-flow.
func generateTestClientCert(t *testing.T) (leaf *x509.Certificate, key *ecdsa.PrivateKey, clientID string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	leaf = testcert.SelfSigned(t, "test-verifier-client", &key.PublicKey, key)
	sum := sha256.Sum256(leaf.Raw)
	clientID = "x509_hash:" + base64.RawURLEncoding.EncodeToString(sum[:])
	return leaf, key, clientID
}

// signRequestObjectPayload builds+signs a Request Object JWS (§5.2)
// under leaf/key carrying every member fetchAndVerifyRequestObject
// needs for a well-formed request plus whatever extra sets — room to
// add the one field under test (e.g. "redirect_uri", "wallet_nonce")
// without duplicating the whole payload per test case. Also returns
// the freshly generated response-encryption private key, so a caller
// standing in as the fake Verifier's own response_uri handler (e.g.
// TestHandleAuthorize_SendsErrorResponseForRedirectURIWithDirectPost)
// can decrypt whatever gets POSTed there.
func signRequestObjectPayload(t *testing.T, leaf *x509.Certificate, key *ecdsa.PrivateKey, clientID string, extra map[string]any) (compact string, encKey *ecdsa.PrivateKey) {
	t.Helper()
	encKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate encryption key: %v", err)
	}
	encJWK, err := jwk.Marshal(&encKey.PublicKey)
	if err != nil {
		t.Fatalf("jwk.Marshal: %v", err)
	}

	payload := map[string]any{
		"client_id":    clientID,
		"response_uri": "https://verifier.example.com/response",
		"nonce":        "test-nonce",
		"state":        "test-state",
		"dcql_query":   map[string]any{"credentials": []any{}},
		"client_metadata": map[string]any{
			"jwks": map[string]any{"keys": []any{encJWK}},
			"encrypted_response_enc_values_supported": []string{"A128GCM"},
		},
	}
	for k, v := range extra {
		payload[k] = v
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	header := map[string]any{
		"typ": "oauth-authz-req+jwt",
		"x5c": []string{base64.StdEncoding.EncodeToString(leaf.Raw)},
	}
	compact, err = jose.Sign(jose.ES256, key, header, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact, encKey
}

// buildSignedRequestObject generates a fresh client identity and
// signs one Request Object under it — the single-request shape every
// GET-fetch test below uses. Returns the signed compact JWS, the
// client_id it was signed under, and the response-encryption private
// key a fake Verifier's own response_uri handler would need to
// decrypt a response (see signRequestObjectPayload's own doc
// comment) — ignored by every existing caller that doesn't need it.
func buildSignedRequestObject(t *testing.T, extra map[string]any) (compact, clientID string, encKey *ecdsa.PrivateKey) {
	t.Helper()
	leaf, key, clientID := generateTestClientCert(t)
	compact, encKey = signRequestObjectPayload(t, leaf, key, clientID, extra)
	return compact, clientID, encKey
}

func serveRequestObject(t *testing.T, compact string) string {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(compact))
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// servePostRequestObject serves a POST-only (§5.10) request_uri
// endpoint that signs a fresh Request Object per request under one
// fixed client identity — mirroring cmd/conformance-verifier's own
// session.ensureBuilt, which likewise only knows the Wallet's own
// wallet_nonce once the POST actually arrives. When echoNonce is
// false, the served object never carries a "wallet_nonce" claim at
// all, regardless of what the POST sent — the negative case for
// fetchAndVerifyRequestObject's own §5.10.1 enforcement.
func servePostRequestObject(t *testing.T, echoNonce bool) (rawURL, clientID string) {
	t.Helper()
	leaf, key, clientID := generateTestClientCert(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			http.Error(w, "want application/x-www-form-urlencoded Content-Type", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Accept") != "application/oauth-authz-req+jwt" {
			http.Error(w, "want application/oauth-authz-req+jwt Accept", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		extra := map[string]any{}
		if echoNonce {
			if nonce := r.PostForm.Get("wallet_nonce"); nonce != "" {
				extra["wallet_nonce"] = nonce
			}
		}
		compact, _ := signRequestObjectPayload(t, leaf, key, clientID, extra)
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(compact))
	}))
	t.Cleanup(ts.Close)
	return ts.URL, clientID
}

// TestFetchAndVerifyRequestObject_RejectsRedirectURI also proves the
// rejection is a *wallet.RequestRejectedError carrying a real
// ResponseURI/ResponseEncryptionKey — not just any error — since the
// Request Object here is otherwise authentic (signature verified,
// client_id matches): handleAuthorize's own caller relies on exactly
// this to send an OID4VP §8.1 error response instead of only
// rejecting locally (see TestHandleAuthorize_SendsErrorResponseForRedirectURIWithDirectPost).
func TestFetchAndVerifyRequestObject_RejectsRedirectURI(t *testing.T) {
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{"redirect_uri": "https://wallet.example.com/callback"})
	url := serveRequestObject(t, compact)
	_, err := fetchAndVerifyRequestObject(url, clientID, false)
	if err == nil {
		t.Fatal("fetchAndVerifyRequestObject accepted a request object carrying redirect_uri alongside response_uri")
	}
	var rejected *wallet.RequestRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %v, want a *wallet.RequestRejectedError", err)
	}
	if rejected.ResponseURI != "https://verifier.example.com/response" {
		t.Errorf("ResponseURI = %q, want the Request Object's own response_uri", rejected.ResponseURI)
	}
	if rejected.ResponseEncryptionKey == nil {
		t.Error("ResponseEncryptionKey is nil, want the Request Object's own client_metadata key")
	}
}

// TestFetchAndVerifyRequestObject_RejectsTransactionData is
// TestFetchAndVerifyRequestObject_RejectsRedirectURI's own
// transaction_data twin.
func TestFetchAndVerifyRequestObject_RejectsTransactionData(t *testing.T) {
	compact, clientID, _ := buildSignedRequestObject(t, map[string]any{"transaction_data": []string{"eyJ0eXBlIjoidW5rbm93biJ9"}})
	url := serveRequestObject(t, compact)
	_, err := fetchAndVerifyRequestObject(url, clientID, false)
	if err == nil {
		t.Fatal("fetchAndVerifyRequestObject accepted a request object carrying transaction_data")
	}
	var rejected *wallet.RequestRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("error = %v, want a *wallet.RequestRejectedError", err)
	}
	if rejected.ResponseURI != "https://verifier.example.com/response" {
		t.Errorf("ResponseURI = %q, want the Request Object's own response_uri", rejected.ResponseURI)
	}
}

func TestFetchAndVerifyRequestObject_AcceptsWellFormedRequest(t *testing.T) {
	compact, clientID, _ := buildSignedRequestObject(t, nil)
	url := serveRequestObject(t, compact)
	req, err := fetchAndVerifyRequestObject(url, clientID, false)
	if err != nil {
		t.Fatalf("fetchAndVerifyRequestObject: %v", err)
	}
	if req.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", req.ClientID, clientID)
	}
}

// TestFetchAndVerifyRequestObject_POSTEchoesWalletNonce is the happy
// path for §5.10.1: this binary sends a fresh wallet_nonce over POST,
// the Verifier echoes it back as the signed object's own
// "wallet_nonce" claim, and fetchAndVerifyRequestObject accepts it.
func TestFetchAndVerifyRequestObject_POSTEchoesWalletNonce(t *testing.T) {
	url, clientID := servePostRequestObject(t, true)
	if _, err := fetchAndVerifyRequestObject(url, clientID, true); err != nil {
		t.Fatalf("fetchAndVerifyRequestObject: %v", err)
	}
}

// TestFetchAndVerifyRequestObject_RejectsMissingWalletNonceEcho is the
// negative case §5.10.1 exists for: a Verifier that ignores the
// wallet_nonce this binary sent (never echoes it into the signed
// object) must be rejected, not silently accepted — otherwise the
// replay-mitigation the nonce exists for is theater, not enforcement.
func TestFetchAndVerifyRequestObject_RejectsMissingWalletNonceEcho(t *testing.T) {
	url, clientID := servePostRequestObject(t, false)
	if _, err := fetchAndVerifyRequestObject(url, clientID, true); err == nil {
		t.Error("fetchAndVerifyRequestObject accepted a POST response whose payload never echoed back the wallet_nonce it sent")
	}
}

// TestHandleAuthorize_SendsErrorResponseForRedirectURIWithDirectPost
// is the full handleAuthorize-level counterpart to
// TestFetchAndVerifyRequestObject_RejectsRedirectURI: not just that
// fetchAndVerifyRequestObject returns a *wallet.RequestRejectedError,
// but that handleAuthorize actually uses it to build and POST a real
// encrypted OID4VP §8.1 error response to response_uri — a fake
// Verifier server decrypts what arrives there with the same
// encryption key the Request Object itself advertised, proving the
// two ends are still genuinely interoperable, not just that
// handleAuthorize's own local HTTP response looks right.
func TestHandleAuthorize_SendsErrorResponseForRedirectURIWithDirectPost(t *testing.T) {
	var captured map[string]any
	responseTS := httptest.NewTLSServer(nil)
	t.Cleanup(responseTS.Close)

	compact, clientID, encKey := buildSignedRequestObject(t, map[string]any{
		"redirect_uri": "https://wallet.example.com/callback",
		"response_uri": responseTS.URL,
	})

	mux := http.NewServeMux()
	responseTS.Config.Handler = mux
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse response_uri POST form: %v", err)
		}
		plaintext, err := jwe.Decrypt(encKey, r.PostForm.Get("response"))
		if err != nil {
			t.Fatalf("decrypt response_uri POST body: %v", err)
		}
		if err := json.Unmarshal(plaintext, &captured); err != nil {
			t.Fatalf("unmarshal decrypted response: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	})

	requestURL := serveRequestObject(t, compact)

	s := &server{cred: wallet.HeldCredential{}}
	target := "https://wallet-under-test.example/authorize?" + url.Values{
		"client_id": {clientID}, "request_uri": {requestURL},
	}.Encode()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	s.handleAuthorize(rec, req)

	if rec.Code != http.StatusOK {
		body, _ := io.ReadAll(rec.Body)
		t.Fatalf("handleAuthorize: status %d: %s", rec.Code, body)
	}
	if !strings.Contains(rec.Body.String(), "Rejected") {
		t.Errorf("response body = %q, want it to mention Rejected", rec.Body.String())
	}
	if captured == nil {
		t.Fatal("response_uri was never called")
	}
	if captured["error"] != "invalid_request" {
		t.Errorf("decrypted response error = %v, want \"invalid_request\"", captured["error"])
	}
	if captured["vp_token"] != nil {
		t.Errorf("decrypted response carries a vp_token %v, want none for an error response", captured["vp_token"])
	}
}
