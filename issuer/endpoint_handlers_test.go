package issuer_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/issuer"
)

func clientGrant(clientID string) *fakeTokens {
	return &fakeTokens{grant: issuer.Grant{
		DPoPNonce:  "next-nonce",
		Authorized: issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID(clientID)},
	}}
}

func protectedEndpoint(t *testing.T, tokens issuer.AccessTokenVerifier) issuer.ProtectedEndpointConfig {
	t.Helper()
	return issuer.ProtectedEndpointConfig{URL: mustURL(t, "https://issuer.example.com/endpoint"), Tokens: tokens}
}

func deferredHandler(t *testing.T, mutate func(*issuer.Config)) (http.Handler, *fakeDeferredTransactionStore) {
	t.Helper()
	store := newFakeDeferredTransactionStore()
	cfg := validConfig(t)
	if mutate != nil {
		mutate(&cfg)
	}
	deps := validDependencies(t)
	deps.DeferredTransactions = store
	h, err := newTestIssuer(t, cfg, deps).DeferredCredentialHandler(protectedEndpoint(t, clientGrant("client-a")))
	if err != nil {
		t.Fatalf("DeferredCredentialHandler: %v", err)
	}
	return h, store
}

func TestDeferredCredentialHandler_Issued(t *testing.T) {
	h, store := deferredHandler(t, nil)
	store.put("txn-1", issuer.DeferredTransactionRecord{
		ClientID: "client-a", Status: issuer.DeferredTransactionIssued,
		Credentials: []oid4vci.IssuedCredential{{Credential: "signed-credential"}}, NotificationID: "notif-1",
	})

	w := postCredentialRequest(t, h, `{"transaction_id":"txn-1"}`)
	if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("DPoP-Nonce") != "next-nonce" {
		t.Fatalf("response = %d %v %s", w.Code, w.Header(), w.Body)
	}
	var body struct {
		Credentials    []oid4vci.IssuedCredential `json:"credentials"`
		NotificationID string                     `json:"notification_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Credentials) != 1 || body.NotificationID != "notif-1" {
		t.Errorf("body = %s (%v)", w.Body, err)
	}
}

func TestDeferredCredentialHandler_Pending(t *testing.T) {
	h, store := deferredHandler(t, nil)
	store.put("txn-2", issuer.DeferredTransactionRecord{ClientID: "client-a", Status: issuer.DeferredTransactionPending})

	w := postCredentialRequest(t, h, `{"transaction_id":"txn-2"}`)
	var body struct {
		TransactionID string `json:"transaction_id"`
		Interval      int64  `json:"interval"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusAccepted || body.TransactionID != "txn-2" || body.Interval <= 0 {
		t.Errorf("response = %d %s (%v), want 202 with transaction_id and interval", w.Code, w.Body, err)
	}
}

func TestDeferredCredentialHandler_EncryptsResponse(t *testing.T) {
	var requestKey issuer.RequestDecryptionKey
	h, store := deferredHandler(t, func(cfg *issuer.Config) {
		requestKey = testRequestDecryptionKey(t, "req-1")
		cfg.RequestEncryption = &issuer.RequestEncryptionSupport{Keys: []issuer.RequestDecryptionKey{requestKey}, EncValuesSupported: []jwe.Enc{jwe.A128GCM}}
		cfg.ResponseEncryption = &issuer.ResponseEncryptionSupport{EncValuesSupported: []jwe.Enc{jwe.A128GCM}}
	})
	store.put("txn-3", issuer.DeferredTransactionRecord{ClientID: "client-a", Status: issuer.DeferredTransactionPending})

	plain, err := json.Marshal(map[string]any{
		"transaction_id":                 "txn-3",
		"credential_response_encryption": map[string]any{"jwk": testWalletJWK(t), "enc": "A128GCM"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := jwe.Encrypt(&requestKey.PrivateKey.PublicKey, jwe.A128GCM, plain, jwe.EncryptOptions{KeyID: "req-1"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/deferred", strings.NewReader(encrypted))
	r.Header.Set("Content-Type", "application/jwt")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted || w.Header().Get("Content-Type") != "application/jwt" || strings.Count(w.Body.String(), ".") != 4 {
		t.Errorf("response = %d %q %s, want an encrypted 202", w.Code, w.Header().Get("Content-Type"), w.Body)
	}
}

func TestDeferredCredentialHandler_Refusals(t *testing.T) {
	h, store := deferredHandler(t, nil)
	store.put("txn-4", issuer.DeferredTransactionRecord{ClientID: "client-b", Status: issuer.DeferredTransactionPending})
	for name, c := range map[string]struct {
		body string
		code issuer.ErrorCode
	}{
		"not an object":  {`["txn"]`, issuer.ErrorInvalidCredentialRequest},
		"no transaction": {`{}`, issuer.ErrorInvalidCredentialRequest},
		"unknown":        {`{"transaction_id":"nope"}`, issuer.ErrorInvalidTransactionID},
		"other client":   {`{"transaction_id":"txn-4"}`, issuer.ErrorInvalidTransactionID},
		"too large":      {`{"transaction_id":"` + strings.Repeat("a", issuer.MaxCredentialRequestBytes) + `"}`, issuer.ErrorInvalidCredentialRequest},
	} {
		t.Run(name, func(t *testing.T) {
			assertCredentialErrorResponse(t, postCredentialRequest(t, h, c.body), http.StatusBadRequest, c.code)
		})
	}
}

func notificationHandler(t *testing.T) (http.Handler, *fakeNotificationStore, *fakeNotificationHandler, *fakeTokens) {
	t.Helper()
	store, events, tokens := newFakeNotificationStore(), &fakeNotificationHandler{}, clientGrant("client-a")
	deps := validDependencies(t)
	deps.Notifications, deps.NotificationHandler = store, events
	h, err := newTestIssuer(t, validConfig(t), deps).NotificationEndpointHandler(protectedEndpoint(t, tokens))
	if err != nil {
		t.Fatalf("NotificationEndpointHandler: %v", err)
	}
	return h, store, events, tokens
}

func TestNotificationEndpointHandler(t *testing.T) {
	h, store, events, tokens := notificationHandler(t)
	store.put("notif-1", issuer.NotificationRecord{ClientID: "client-a"})

	w := postCredentialRequest(t, h, `{"notification_id":"notif-1","event":"credential_accepted","event_description":"stored"}`)
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("response = %d %s, want 204 with no body", w.Code, w.Body)
	}
	if len(events.calls) != 1 || events.calls[0].Event != oid4vci.NotificationEventCredentialAccepted {
		t.Errorf("handler calls = %+v", events.calls)
	}

	for name, c := range map[string]struct {
		body string
		code issuer.ErrorCode
	}{
		"not an object": {`"x"`, issuer.ErrorInvalidNotificationRequest},
		"bad event":     {`{"notification_id":"notif-1","event":"credential_lost"}`, issuer.ErrorInvalidNotificationRequest},
		"unknown id":    {`{"notification_id":"nope","event":"credential_deleted"}`, issuer.ErrorInvalidNotificationID},
		"too large":     {`{"notification_id":"notif-1","event":"credential_deleted","event_description":"` + strings.Repeat("a", issuer.MaxNotificationRequestBytes) + `"}`, issuer.ErrorInvalidNotificationRequest},
	} {
		t.Run(name, func(t *testing.T) {
			assertCredentialErrorResponse(t, postCredentialRequest(t, h, c.body), http.StatusBadRequest, c.code)
		})
	}

	tokens.err = errors.New("expired")
	if w := postCredentialRequest(t, h, `{}`); w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want the token verifier's 401", w.Code)
	}
}

func TestProtectedEndpointHandlers_RequireConfig(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	for name, cfg := range map[string]issuer.ProtectedEndpointConfig{
		"no URL":       {Tokens: &fakeTokens{}},
		"relative URL": {URL: &url.URL{Path: "/x"}, Tokens: &fakeTokens{}},
		"no Tokens":    {URL: mustURL(t, "https://issuer.example.com/x")},
	} {
		if _, err := iss.DeferredCredentialHandler(cfg); err == nil {
			t.Errorf("DeferredCredentialHandler(%s) succeeded", name)
		}
		if _, err := iss.NotificationEndpointHandler(cfg); err == nil {
			t.Errorf("NotificationEndpointHandler(%s) succeeded", name)
		}
	}
	if _, err := iss.DeferredCredentialHandler(protectedEndpoint(t, &fakeTokens{})); err != nil {
		t.Errorf("DeferredCredentialHandler: %v", err)
	}
}
