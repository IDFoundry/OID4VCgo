package issuer_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/oid4vcigo/issuer"
)

func TestRequestNonce(t *testing.T) {
	nonces := newFakeNonceStore()
	now := time.Now()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Nonces = nonces
	deps.Clock = fixedClock{now: now}

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	result, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if result.CNonce == "" {
		t.Fatalf("CNonce is empty")
	}

	// Consuming the returned nonce must succeed exactly once.
	record, err := nonces.Consume(context.Background(), issuer.NonceConsumption{Nonce: result.CNonce})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	wantExpiry := now.Add(cfg.Limits.NonceLifetime)
	if !record.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, wantExpiry)
	}
	if _, err := nonces.Consume(context.Background(), issuer.NonceConsumption{Nonce: result.CNonce}); err == nil {
		t.Errorf("Consume accepted the same nonce twice")
	}
}

func TestRequestNonce_ProducesDistinctValues(t *testing.T) {
	cfg := validConfig(t)
	iss, err := issuer.New(cfg, validDependencies(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	first, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	second, err := iss.RequestNonce(context.Background())
	if err != nil {
		t.Fatalf("RequestNonce: %v", err)
	}
	if first.CNonce == second.CNonce {
		t.Errorf("two nonces were identical: %q", first.CNonce)
	}
}

func TestRequestNonce_RejectsWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.Endpoints.Nonce = fapi.URL{}
	cfg.Limits.NonceLifetime = 0
	deps := validDependencies(t)
	deps.Nonces = nil

	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := iss.RequestNonce(context.Background()); err == nil {
		t.Errorf("RequestNonce succeeded with no Nonce Endpoint configured")
	}
}

func TestRequestNonce_PropagatesRandomError(t *testing.T) {
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Random = errReader{}
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := iss.RequestNonce(context.Background()); err == nil {
		t.Errorf("RequestNonce succeeded despite a failing random source")
	}
}

func TestRequestNonce_PropagatesStoreError(t *testing.T) {
	cfg := validConfig(t)
	nonces := newFakeNonceStore()
	nonces.issueErr = errNonceNotFound
	deps := validDependencies(t)
	deps.Nonces = nonces
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := iss.RequestNonce(context.Background()); err == nil {
		t.Errorf("RequestNonce succeeded despite a failing NonceStore.Issue")
	}
}

func TestNonceResult_WriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	issuer.NonceResult{CNonce: "abc123"}.WriteJSON(rec)

	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if rec.Code != 200 {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	want := `{"c_nonce":"abc123"}`
	if got := rec.Body.String(); got != want {
		t.Errorf("body = %q, want %q", got, want)
	}
}
