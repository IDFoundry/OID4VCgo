package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/jwk"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
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
// without duplicating the whole payload per test case.
func signRequestObjectPayload(t *testing.T, leaf *x509.Certificate, key *ecdsa.PrivateKey, clientID string, extra map[string]any) string {
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
	compact, err := jose.Sign(jose.ES256, key, header, raw)
	if err != nil {
		t.Fatalf("jose.Sign: %v", err)
	}
	return compact
}

// buildSignedRequestObject generates a fresh client identity and
// signs one Request Object under it — the single-request shape every
// GET-fetch test below uses. Returns the signed compact JWS and the
// client_id it was signed under.
func buildSignedRequestObject(t *testing.T, extra map[string]any) (compact, clientID string) {
	t.Helper()
	leaf, key, clientID := generateTestClientCert(t)
	return signRequestObjectPayload(t, leaf, key, clientID, extra), clientID
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
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			http.Error(w, "want application/x-www-form-urlencoded Content-Type", http.StatusBadRequest)
			return
		}
		if accept := r.Header.Get("Accept"); accept != "application/oauth-authz-req+jwt" {
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
		compact := signRequestObjectPayload(t, leaf, key, clientID, extra)
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte(compact))
	}))
	t.Cleanup(ts.Close)
	return ts.URL, clientID
}

func TestFetchAndVerifyRequestObject_RejectsRedirectURI(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, map[string]any{"redirect_uri": "https://wallet.example.com/callback"})
	url := serveRequestObject(t, compact)
	if _, err := fetchAndVerifyRequestObject(url, clientID, false); err == nil {
		t.Error("fetchAndVerifyRequestObject accepted a request object carrying redirect_uri alongside response_uri")
	}
}

func TestFetchAndVerifyRequestObject_RejectsTransactionData(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, map[string]any{"transaction_data": []string{"eyJ0eXBlIjoidW5rbm93biJ9"}})
	url := serveRequestObject(t, compact)
	if _, err := fetchAndVerifyRequestObject(url, clientID, false); err == nil {
		t.Error("fetchAndVerifyRequestObject accepted a request object carrying transaction_data")
	}
}

func TestFetchAndVerifyRequestObject_AcceptsWellFormedRequest(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, nil)
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
