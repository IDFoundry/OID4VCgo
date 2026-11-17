package walletprovider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// The older protocol's attestation endpoints, which need no challenge,
// are rate-limited for each client address, as its challenge endpoint
// is: each new instance key registers an instance.
func TestService_LimitsLegacyAttestations(t *testing.T) {
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.newService(ServiceConfig{ClientID: "wallet-1", Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	h := s.handler(true)
	post := func(path, body, from string) int {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.RemoteAddr = from
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	newKeyRequest := func() string {
		jwk, err := attestation.AttestedKey(&p256(t).PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(WalletAttestationRequest{ClientID: "wallet-1", InstanceKey: jwk})
		return string(body)
	}
	const from = "203.0.113.9:40000"
	for i := range int(attestationBurst) {
		if code := post(WalletAttestationPath, newKeyRequest(), from); code != http.StatusOK {
			t.Fatalf("request %d within the burst: status %d", i+1, code)
		}
	}
	if code := post(WalletAttestationPath, newKeyRequest(), from); code != http.StatusTooManyRequests {
		t.Errorf("Wallet Attestation past the burst: status %d, want 429", code)
	}
	if code := post(KeyAttestationPath, `{}`, from); code != http.StatusTooManyRequests {
		t.Errorf("Key Attestation past the burst: status %d, want 429", code)
	}
	if code := post(WalletAttestationPath, newKeyRequest(), "198.51.100.1:1"); code != http.StatusOK {
		t.Errorf("another address: status %d, want 200", code)
	}
}

// The instances the older protocol registers are bounded, the least
// recently seen going first, and expire after demoInstanceIdle; the
// shared Key Attestation instance stays, and a wallet whose instance
// went gets a new one.
func TestService_PrunesLegacyInstances(t *testing.T) {
	ctx := context.Background()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s, err := p.newService(ServiceConfig{
		ClientID: "wallet-1", Logf: func(string, ...any) {}, Now: func() time.Time { return now },
		InstancesPath: filepath.Join(t.TempDir(), "instances.json"),
	})
	if err != nil {
		t.Fatal(err)
	}
	holder, _, err := s.holderIssuance(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var thumbprints []string
	for range 3 {
		now = now.Add(time.Minute)
		thumbprints = append(thumbprints, attestNewKey(t, s))
	}

	if n, err := s.store.pruneDemoInstances(now.Add(-demoInstanceIdle), 1); err != nil || n != 2 {
		t.Fatalf("pruning to 1: %d pruned, %v; want 2", n, err)
	}
	for i, tp := range thumbprints {
		_, err := s.instanceOf(ctx, tp)
		if errors.Is(err, wp.ErrNotFound) != (i < 2) {
			t.Errorf("instance key %d: lookup %v; want only the two least recently seen gone", i, err)
		}
	}

	now = now.Add(demoInstanceIdle + time.Minute)
	if n, err := s.store.pruneDemoInstances(now.Add(-demoInstanceIdle), maxDemoInstances); err != nil || n != 1 {
		t.Fatalf("pruning idle instances: %d pruned, %v; want 1", n, err)
	}
	if _, err := s.store.Get(ctx, holder); err != nil {
		t.Errorf("the shared Key Attestation instance was pruned: %v", err)
	}
	if n := countInstances(t, s); n != 1 {
		t.Errorf("%d instances left, want only the shared one", n)
	}
	attestNewKey(t, s) // a Wallet Attestation after pruning registers anew
}

// attestNewKey has s issue a Wallet Attestation for a new instance key,
// returning its thumbprint.
func attestNewKey(t *testing.T, s *service) string {
	t.Helper()
	key := p256(t)
	tp := thumbprintOf(t, &key.PublicKey)
	if _, _, err := s.libWalletAttestation(context.Background(), &key.PublicKey, tp, wp.SecurityLevelSoftware); err != nil {
		t.Fatal(err)
	}
	return tp
}
