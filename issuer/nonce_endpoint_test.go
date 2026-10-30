package issuer_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/oid4vcgo/issuer"
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
	record, err := nonces.Consume(context.Background(), issuer.NonceConsumption{Owner: testIssuer, Nonce: result.CNonce})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	wantExpiry := now.Add(cfg.Limits.NonceLifetime)
	if !record.ExpiresAt.Equal(wantExpiry) {
		t.Errorf("ExpiresAt = %v, want %v", record.ExpiresAt, wantExpiry)
	}
	if record.Owner != testIssuer {
		t.Errorf("Owner = %q, want the Credential Issuer, %q", record.Owner, testIssuer)
	}
	if _, err := nonces.Consume(context.Background(), issuer.NonceConsumption{Owner: testIssuer, Nonce: result.CNonce}); err == nil {
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
	cfg.Limits.MaxProofAge = time.Minute
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

// fakeCredentialDPoPNonces is a CredentialDPoPNonceIssuer handing out
// nonce, or failing with err.
type fakeCredentialDPoPNonces struct {
	nonce string
	err   error
}

func (f fakeCredentialDPoPNonces) IssueDPoPNonce(context.Context) (string, error) {
	return f.nonce, f.err
}

// TestRequestNonce_CarriesACredentialDPoPNonce: with
// Dependencies.CredentialDPoPNonces, the Nonce Response carries a DPoP
// nonce from it in its DPoP-Nonce header (§7.2), for the Wallet to use
// at the Credential Endpoint; a failing issuer fails the request; none
// configured, or none given, sends no header.
func TestRequestNonce_CarriesACredentialDPoPNonce(t *testing.T) {
	newIssuer := func(dpop issuer.CredentialDPoPNonceIssuer) *issuer.Issuer {
		cfg := validConfig(t)
		deps := validDependencies(t)
		deps.CredentialDPoPNonces = dpop
		iss, err := issuer.New(cfg, deps)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return iss
	}
	ctx := context.Background()

	result, err := newIssuer(fakeCredentialDPoPNonces{nonce: "dpop-1"}).RequestNonce(ctx)
	if err != nil || result.DPoPNonce != "dpop-1" {
		t.Fatalf("RequestNonce = %+v, %v; want DPoPNonce dpop-1", result, err)
	}
	rec := httptest.NewRecorder()
	result.WriteJSON(rec)
	if got := rec.Header().Get("DPoP-Nonce"); got != "dpop-1" {
		t.Errorf("DPoP-Nonce header = %q, want dpop-1", got)
	}

	if _, err := newIssuer(fakeCredentialDPoPNonces{err: errors.New("store down")}).RequestNonce(ctx); err == nil {
		t.Error("RequestNonce with a failing CredentialDPoPNonces = nil error, want error")
	}

	for name, dpop := range map[string]issuer.CredentialDPoPNonceIssuer{"none configured": nil, "none given": fakeCredentialDPoPNonces{}} {
		result, err := newIssuer(dpop).RequestNonce(ctx)
		if err != nil {
			t.Fatalf("%s: RequestNonce: %v", name, err)
		}
		rec := httptest.NewRecorder()
		result.WriteJSON(rec)
		if _, sent := rec.Header()["Dpop-Nonce"]; sent {
			t.Errorf("%s: a DPoP-Nonce header was sent", name)
		}
	}
}
