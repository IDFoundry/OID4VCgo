package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// TestNonceHandler_HidesErrors: a Nonce Endpoint failure is answered
// with server_error alone, never the error's text, which can name the
// store's database, host or user, to its anonymous callers.
func TestNonceHandler_HidesErrors(t *testing.T) {
	h := nonceHandler(func(context.Context) (issuer.NonceResult, error) {
		return issuer.NonceResult{}, errors.New(`store nonce: failed to connect to user=oid4vc database=issuer host=db.internal`)
	})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/nonce", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || strings.TrimSpace(body) != "server_error" {
		t.Fatalf("POST /nonce = %d %q, want 500 server_error", rec.Code, body)
	}
	for _, leaked := range []string{"db.internal", "oid4vc", "store nonce"} {
		if strings.Contains(body, leaked) {
			t.Errorf("the answer carries %q: %q", leaked, body)
		}
	}
}
