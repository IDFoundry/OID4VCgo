package androidkey_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// statusProvider is a provider whose Android Verifier checks revocation
// with src, under ca's root.
func statusProvider(t *testing.T, src *androidkey.StatusSource) (*providerFixture, attestationCA) {
	ca := newAttestationCA(t)
	v := &androidkey.Verifier{Roots: []*x509.Certificate{ca.root}, Revocation: src, Apps: []androidkey.AllowedApp{testApp}}
	return newProviderFixture(t, androidkey.EvidenceVerifier{Verifier: v}), ca
}

// registerWith registers an instance through f with a fresh chain
// under ca.
func registerWith(ctx context.Context, t *testing.T, f *providerFixture, ca attestationCA, serial int64) (string, testChain, error) {
	t.Helper()
	ch, raw := f.challenge(t, walletprovider.PurposeRegistration)
	c := ca.chain(t, serial, raw)
	id, err := f.client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &c.leafKey.PublicKey, Evidence: androidkey.Evidence(c.der),
	})
	return id, c, err
}

// TestStatusSource_HungUpRegistration: a client hanging up on the
// registration whose request started the status list's fetch fails
// only its own registration: the fetch completes, and the next
// registrations are verified against the list it fetched, with no
// fetch of their own.
func TestStatusSource_HungUpRegistration(t *testing.T) {
	srv := newGatedStatusServer(t)
	f, ca := statusProvider(t, srv.source(t, &testClock{t: statusEpoch}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, _, err := registerWith(ctx, t, f, ca, 100)
		done <- err
	}()
	<-srv.arrived
	cancel()
	if err := <-done; err == nil {
		t.Fatal("the hung-up registration completed")
	}
	srv.release <- struct{}{}
	for i := range 3 {
		if _, _, err := registerWith(context.Background(), t, f, ca, int64(200+10*i)); err != nil {
			t.Fatalf("registration %d after the hang-up: %v", i, err)
		}
	}
	if n := srv.requests.Load(); n != 1 {
		t.Fatalf("%d status list requests, want the one fetch", n)
	}
}

// TestStatusSource_UnavailableIsRetryable: with no status list to be
// had, an Android registration, and the recheck of a registered
// instance, are answered 503 server_error, for the wallet to try
// again, not evidence_rejected; the instance is left active and the
// refusal unreported.
func TestStatusSource_UnavailableIsRetryable(t *testing.T) {
	srv := newStatusServer(t)
	clock := &testClock{t: statusEpoch}
	src := srv.source(t, clock)
	src.Grace = -1
	f, ca := statusProvider(t, src)
	ctx := context.Background()
	id, reg, err := registerWith(ctx, t, f, ca, 100)
	if err != nil {
		t.Fatal(err)
	}

	srv.fail.Store(true)
	clock.set(statusEpoch.Add(androidkey.DefaultStatusMaxAge))
	expect503 := func(what string, err error) {
		t.Helper()
		var refused *walletprovider.RefusedError
		if !errors.As(err, &refused) || refused.Status != http.StatusServiceUnavailable || refused.Code != "server_error" {
			t.Fatalf("%s with no status list = %v, want 503 server_error", what, err)
		}
	}
	_, _, err = registerWith(ctx, t, f, ca, 200)
	expect503("a registration", err)

	ch, raw := f.challenge(t, walletprovider.PurposeInstance)
	ik := ca.chain(t, 300, raw)
	_, err = f.client.WalletAttestation(ctx, reg.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: id, ClientID: "wallet", InstanceKey: &ik.leafKey.PublicKey, Challenge: ch, Evidence: androidkey.Evidence(ik.der),
	})
	expect503("a registered instance's Wallet Attestation", err)
	if state := f.state(t, id); state != walletprovider.StateActive {
		t.Fatalf("the instance is %s, want active", state)
	}
	if n := len(f.refusals()); n != 0 {
		t.Fatalf("OnRecheckRefused called %d times, want none", n)
	}
}
