package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/idfoundry/oid4vcigo/internal/jose"
	"github.com/idfoundry/oid4vcigo/internal/jwk"
	"github.com/idfoundry/oid4vcigo/internal/testcert"
)

// buildSignedRequestObject generates a fresh throwaway leaf
// certificate, computes its own x509_hash Client ID, and builds+signs
// a Request Object JWS (§5.2) for it carrying every member
// fetchAndVerifyRequestObject needs for a well-formed request plus
// whatever extra sets — room to add the one field under test (e.g.
// "redirect_uri", "transaction_data") without duplicating the whole
// payload per test case. Returns the signed compact JWS and the
// client_id it was signed under.
func buildSignedRequestObject(t *testing.T, extra map[string]any) (compact, clientID string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	leaf := testcert.SelfSigned(t, "test-verifier-client", &key.PublicKey, key)
	sum := sha256.Sum256(leaf.Raw)
	clientID = "x509_hash:" + base64.RawURLEncoding.EncodeToString(sum[:])

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
	return compact, clientID
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

func TestFetchAndVerifyRequestObject_RejectsRedirectURI(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, map[string]any{"redirect_uri": "https://wallet.example.com/callback"})
	url := serveRequestObject(t, compact)
	if _, err := fetchAndVerifyRequestObject(url, clientID); err == nil {
		t.Error("fetchAndVerifyRequestObject accepted a request object carrying redirect_uri alongside response_uri")
	}
}

func TestFetchAndVerifyRequestObject_RejectsTransactionData(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, map[string]any{"transaction_data": []string{"eyJ0eXBlIjoidW5rbm93biJ9"}})
	url := serveRequestObject(t, compact)
	if _, err := fetchAndVerifyRequestObject(url, clientID); err == nil {
		t.Error("fetchAndVerifyRequestObject accepted a request object carrying transaction_data")
	}
}

func TestFetchAndVerifyRequestObject_AcceptsWellFormedRequest(t *testing.T) {
	compact, clientID := buildSignedRequestObject(t, nil)
	url := serveRequestObject(t, compact)
	req, err := fetchAndVerifyRequestObject(url, clientID)
	if err != nil {
		t.Fatalf("fetchAndVerifyRequestObject: %v", err)
	}
	if req.ClientID != clientID {
		t.Errorf("ClientID = %q, want %q", req.ClientID, clientID)
	}
}
