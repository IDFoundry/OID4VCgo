package walletprovider

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	wp "github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/appattest"
)

// TestIOSAppsFlag: each value is one App ID, a 10-character team ID
// and a bundle ID.
func TestIOSAppsFlag(t *testing.T) {
	var f IOSAppsFlag
	for _, v := range []string{"ABCDE12345.dev.idfoundry.oid4vcgo.demowallet", "ZYXWV98765.com.example.wallet"} {
		if err := f.Set(v); err != nil {
			t.Fatalf("Set(%q): %v", v, err)
		}
	}
	if got := f.String(); got != "ABCDE12345.dev.idfoundry.oid4vcgo.demowallet ZYXWV98765.com.example.wallet" {
		t.Errorf("String() = %q", got)
	}
	for _, bad := range []string{"", "dev.idfoundry.oid4vcgo.demowallet", "ABCDE12345", "ABCDE12345.", "abcde12345.com.example", "ABCDE1234.com.example", "ABCDE12345.com example"} {
		if err := f.Set(bad); err == nil {
			t.Errorf("Set(%q) accepted", bad)
		}
	}
}

// TestService_V1TakesAppAttestWithIOSApps: without IOSApps, /v1/ takes
// no App Attest evidence (unsupported_evidence); with them, it verifies
// it, refusing an attestation object Apple didn't make
// (evidence_rejected).
func TestService_V1TakesAppAttestWithIOSApps(t *testing.T) {
	for _, tc := range []struct {
		apps []string
		want string
	}{
		{nil, "unsupported_evidence"},
		{[]string{"ABCDE12345.dev.idfoundry.oid4vcgo.demowallet"}, "evidence_rejected"},
	} {
		p, err := New(testIssuer)
		if err != nil {
			t.Fatal(err)
		}
		s, err := p.newService(ServiceConfig{ClientID: "wallet-1", IOSApps: tc.apps, Logf: func(string, ...any) {}})
		if err != nil {
			t.Fatal(err)
		}
		srv := httptest.NewTLSServer(s.handler(len(tc.apps) == 0))
		ctx := context.Background()
		wc, err := wp.NewClient(srv.URL, wp.ClientOptions{HTTP: srv.Client()})
		if err != nil {
			t.Fatal(err)
		}
		ch, err := wc.Challenge(ctx, wp.PurposeRegistration)
		if err != nil {
			t.Fatal(err)
		}
		key := p256(t)
		_, err = wc.Register(ctx, wp.RegisterRequest{
			Challenge: ch.Value, RegistrationKey: &key.PublicKey, Evidence: appattest.Evidence([]byte{0xa0}),
		})
		if code := refusal(t, err); code != tc.want {
			t.Errorf("IOSApps %v: App Attest evidence over /v1: %s, want %s", tc.apps, code, tc.want)
		}
		srv.Close()
	}
}

// TestService_IOSAppsTurnOffTheDemoProtocol: with IOSApps the older
// protocol's endpoints answer 403, and attest nothing, while an
// in-process client still gets attestations from them; without
// IOSApps the endpoints answer as before.
func TestService_IOSAppsTurnOffTheDemoProtocol(t *testing.T) {
	ctx := context.Background()
	p, err := New(testIssuer)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewService(ServiceConfig{ClientID: "wallet-1", IOSApps: []string{"ABCDE12345.dev.idfoundry.oid4vcgo.demowallet"}, Logf: func(string, ...any) {}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	defer srv.Close()
	outside := Client{URL: srv.URL, HTTP: srv.Client()}
	key := &p256(t).PublicKey
	if _, err := outside.WalletAttestation(ctx, "wallet-1", key); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("Wallet Attestation over the demo protocol with IOSApps: %v, want HTTP 403", err)
	}
	if _, err := outside.KeyAttestation(ctx, key, []*ecdsa.PublicKey{key}, "n"); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("Key Attestation over the demo protocol with IOSApps: %v, want HTTP 403", err)
	}
	resp, err := srv.Client().Post(srv.URL+ChallengePath, "application/json", strings.NewReader(`{"purpose":"instance"}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a challenge over the demo protocol with IOSApps: HTTP %d, want 403", resp.StatusCode)
	}

	inside := Client{URL: "https://127.0.0.1:6443", HTTP: s.InProcessClient()}
	if _, err := inside.WalletAttestation(ctx, "wallet-1", key); err != nil {
		t.Fatalf("Wallet Attestation in process: %v", err)
	}
	if _, err := inside.KeyAttestation(ctx, key, []*ecdsa.PublicKey{key}, "n"); err != nil {
		t.Fatalf("Key Attestation in process: %v", err)
	}

	// Without IOSApps, the endpoints attest as before.
	_, open := newService(t)
	if _, err := open.WalletAttestation(ctx, "wallet-1", key); err != nil {
		t.Fatalf("Wallet Attestation without IOSApps: %v", err)
	}
}
