package appattest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// registered is an app registered with a testProvider, and an instance
// key the provider has recorded for it.
type registered struct {
	*app
	tp          *testProvider
	instanceID  string
	instanceKey *ecdsa.PrivateKey
}

// register registers a with tp and records an instance key for it.
func (a *app) register(tp *testProvider) *registered {
	a.t.Helper()
	ctx := context.Background()
	ch := tp.challenge(walletprovider.PurposeRegistration)
	instanceID, err := tp.client.Register(ctx, walletprovider.RegisterRequest{
		Challenge: ch, RegistrationKey: &a.registrationKey.PublicKey, Evidence: a.attest(ch, &a.registrationKey.PublicKey),
	})
	if err != nil {
		a.t.Fatalf("Register: %v", err)
	}
	r := &registered{app: a, tp: tp, instanceID: instanceID, instanceKey: newKey(a.t, elliptic.P256())}
	ch = tp.challenge(walletprovider.PurposeInstance)
	if _, err := tp.client.WalletAttestation(ctx, a.registrationKey, walletprovider.WalletAttestationRequest{
		InstanceID: instanceID, ClientID: "wallet", InstanceKey: &r.instanceKey.PublicKey,
		Challenge: ch, Evidence: a.assert(walletprovider.PurposeInstance, ch, &r.instanceKey.PublicKey),
	}); err != nil {
		a.t.Fatalf("WalletAttestation: %v", err)
	}
	return r
}

// renew asks for a Wallet Attestation for the recorded instance key,
// without evidence.
func (r *registered) renew() error {
	_, err := r.tp.client.WalletAttestation(context.Background(), r.registrationKey, walletprovider.WalletAttestationRequest{
		InstanceID: r.instanceID, ClientID: "wallet", InstanceKey: &r.instanceKey.PublicKey,
	})
	return err
}

// keyAttestation asks for a Key Attestation for a new holder key, with
// a fresh assertion.
func (r *registered) keyAttestation() error {
	holder := []crypto.PublicKey{&newKey(r.t, elliptic.P256()).PublicKey}
	ch := r.tp.challenge(walletprovider.PurposeHolder)
	_, err := r.tp.client.KeyAttestation(context.Background(), r.registrationKey, walletprovider.KeyAttestationRequest{
		InstanceID: r.instanceID, InstanceKey: &r.instanceKey.PublicKey, Challenge: ch, Nonce: "c-nonce",
		Keys: holder, Evidence: []walletprovider.Evidence{r.assert(walletprovider.PurposeHolder, ch, holder...)},
	})
	return err
}

// TestEvidenceVerifierRecheck: unsetting AllowDevelopment, or removing
// the app from Apps, refuses the instances registered before the
// change at their next Wallet Attestation, for an instance key recorded
// before (which needs no evidence) too, and their Key Attestations.
// The refusal is a policy one: OnRecheckRefused hears of it, the
// instance stays active, and restoring the setting lets it through.
func TestEvidenceVerifierRecheck(t *testing.T) {
	apple := newFakeApple(t)
	v := apple.verifier()
	v.AllowDevelopment = true
	var refusals []error
	tp := newTestProvider(t, v, func(_ context.Context, in walletprovider.Instance, err error) {
		if in.State != walletprovider.StateActive {
			t.Errorf("OnRecheckRefused: instance %s, want active", in.State)
		}
		refusals = append(refusals, err)
	})
	dev := (&app{t: t, apple: apple, registrationKey: newKey(t, elliptic.P256())}).register(tp)
	prod := (&app{t: t, apple: apple, registrationKey: newKey(t, elliptic.P256()), production: true}).register(tp)

	wantRefused := func(what string, err, kind error) {
		t.Helper()
		var refused *walletprovider.RefusedError
		if !errors.As(err, &refused) || refused.Code != "policy_refused" {
			t.Fatalf("%s: %v, want policy_refused", what, err)
		}
		if len(refusals) == 0 {
			t.Fatalf("%s: OnRecheckRefused wasn't called", what)
		}
		last := refusals[len(refusals)-1]
		if !errors.Is(last, walletprovider.ErrPolicy) || !errors.Is(last, kind) {
			t.Fatalf("%s: OnRecheckRefused got %v, want ErrPolicy and %v", what, last, kind)
		}
		in, gerr := tp.instances.Get(context.Background(), dev.instanceID)
		if gerr != nil || in.State != walletprovider.StateActive {
			t.Fatalf("%s: instance %s, %v; want active", what, in.State, gerr)
		}
	}
	wantAccepted := func(what string, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
	}

	// Production cutover.
	v.AllowDevelopment = false
	wantRefused("a development instance's renewal", dev.renew(), ErrEnvironment)
	wantRefused("a development instance's Key Attestation", dev.keyAttestation(), ErrEnvironment)
	wantAccepted("a production instance's renewal", prod.renew())
	wantAccepted("a production instance's Key Attestation", prod.keyAttestation())
	v.AllowDevelopment = true
	wantAccepted("a development instance's renewal, development allowed again", dev.renew())

	// The app withdrawn.
	apps := v.Apps
	v.Apps = []string{"ZZZZZ99999.dev.example.other"}
	wantRefused("a withdrawn app's renewal", dev.renew(), ErrAppNotAllowed)
	wantRefused("a withdrawn app's Key Attestation", dev.keyAttestation(), ErrAppNotAllowed)
	wantRefused("a withdrawn app's production renewal", prod.renew(), ErrAppNotAllowed)
	v.Apps = apps
	wantAccepted("a development instance's renewal, the app allowed again", dev.renew())
	wantAccepted("a development instance's Key Attestation, the app allowed again", dev.keyAttestation())
}

// TestEvidenceVerifierRecheckFails: a Verifier that can't judge, or an
// instance whose Credential isn't an App Attest key, is the provider's
// own failure, not a policy refusal.
func TestEvidenceVerifierRecheckFails(t *testing.T) {
	apple := newFakeApple(t)
	attestKey := newKey(t, elliptic.P256())
	credential, err := encodeCredential(&attestKey.PublicKey, EnvironmentProduction)
	if err != nil {
		t.Fatal(err)
	}
	good := walletprovider.Instance{Credential: credential, Evidence: walletprovider.EvidenceSummary{Kind: EvidenceKind, AppID: testAppID}}
	malformed := good
	malformed.Credential = credential[:10]
	for _, tc := range []struct {
		name string
		e    EvidenceVerifier
		in   walletprovider.Instance
	}{
		{name: "no Verifier", e: EvidenceVerifier{}, in: good},
		{name: "no Apps", e: EvidenceVerifier{Verifier: &Verifier{}}, in: good},
		{name: "a malformed Credential", e: EvidenceVerifier{Verifier: apple.verifier()}, in: malformed},
		{name: "no Credential", e: EvidenceVerifier{Verifier: apple.verifier()}, in: walletprovider.Instance{Evidence: good.Evidence}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.e.Recheck(context.Background(), tc.in)
			if !errors.Is(err, ErrConfig) || errors.Is(err, walletprovider.ErrPolicy) {
				t.Fatalf("got %v, want ErrConfig and not ErrPolicy", err)
			}
		})
	}
	if err := (EvidenceVerifier{Verifier: apple.verifier()}).Recheck(context.Background(), good); err != nil {
		t.Fatalf("a production instance of an allowed app: %v", err)
	}
}
