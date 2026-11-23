package walletflow

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jwe"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// An authentic request the wallet refuses is answered with an error
// response at its response_uri (OpenID4VP §8.4, §8.5): the Verifier
// is told, not left waiting, and its redirect_uri is passed on.
func TestRefuse_SendsTheErrorResponse(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plain, err := jwe.Decrypt(key, r.PostFormValue("response"))
		if err != nil {
			t.Errorf("decrypt: %v", err)
		}
		_ = json.Unmarshal(plain, &got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"redirect_uri":"https://verifier.example/done"}`))
	}))
	defer ts.Close()
	w, err := New(Config{Development: true}, Dependencies{Keys: NewMemoryKeyStore(), Credentials: NewMemoryCredentialStore(), HTTP: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	err = w.refuse(context.Background(), &wallet.RequestRejectedError{
		Code: "invalid_transaction_data", Description: "unsupported", State: "s1",
		ResponseURI: ts.URL, ResponseEncryptionKey: &key.PublicKey, ResponseEncryptionEnc: "A128GCM",
	})
	var refused *RequestRefusedError
	if !errors.As(err, &refused) || !errors.Is(err, ErrRequestRefused) || refused.RedirectURI != "https://verifier.example/done" {
		t.Fatalf("refuse = %v; want a RequestRefusedError carrying the redirect_uri", err)
	}
	if got["error"] != "invalid_transaction_data" || got["state"] != "s1" {
		t.Errorf("the Verifier got %v", got)
	}

	if msg := err.Error(); !strings.Contains(msg, "invalid_transaction_data: unsupported") || strings.Contains(msg, "wasn't told") {
		t.Errorf("Error() = %q", msg)
	}

	// With nowhere to send it, a key it can't encrypt to, or a
	// response_uri that can't be reached, the refusal stays local, and
	// says so.
	ts.Close()
	for name, r := range map[string]*wallet.RequestRejectedError{
		"no response_uri": {Code: "invalid_request"},
		"bad enc":         {Code: "invalid_request", ResponseURI: ts.URL, ResponseEncryptionKey: &key.PublicKey, ResponseEncryptionEnc: "none"},
		"unreachable":     {Code: "invalid_request", ResponseURI: ts.URL, ResponseEncryptionKey: &key.PublicKey, ResponseEncryptionEnc: "A128GCM"},
	} {
		err := w.refuse(context.Background(), r)
		if !errors.As(err, &refused) || refused.sendErr == nil || !errors.Is(err, ErrRequestRefused) || !errors.Is(err, refused.sendErr) || !strings.Contains(err.Error(), "wasn't told") {
			t.Errorf("%s: refuse = %v", name, err)
		}
	}
}
