package androidkey_test

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/androidkey"
)

// renamedAndroid is the adapter served under a Kind of the integrator's
// own, as Go embedding makes natural.
type renamedAndroid struct{ androidkey.EvidenceVerifier }

func (renamedAndroid) Kind() string { return "android-tee-keyattestation" }

// TestVerify_RenamedKindFailsClosed: served under another Kind than
// EvidenceKind, the adapter's Verify refuses every piece of evidence
// with ErrConfig, so it registers no instance whose rechecks would all
// fail.
func TestVerify_RenamedKindFailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := newAttestationCA(t)
	v := &androidkey.Verifier{Roots: []*x509.Certificate{ca.root}, Revocation: &androidkey.StatusList{}, Apps: []androidkey.AllowedApp{testApp}}
	ev := renamedAndroid{androidkey.EvidenceVerifier{Verifier: v}}
	f := newProviderFixture(t, ev)

	ch, raw := f.challenge(t, walletprovider.PurposeRegistration)
	reg := ca.chain(t, 101, raw)
	evidence := walletprovider.Evidence{Kind: ev.Kind(), Data: slices.Concat(reg.der...)}
	_, err := ev.Verify(ctx, walletprovider.EvidenceInput{
		Evidence: evidence, Challenge: raw, Purpose: walletprovider.PurposeRegistration,
		Keys: []crypto.PublicKey{&reg.leafKey.PublicKey},
	})
	if !errors.Is(err, androidkey.ErrConfig) {
		t.Fatalf("Verify under a renamed Kind = %v, want ErrConfig", err)
	}
	// The provider answers a Verify error as the evidence's refusal.
	var refused *walletprovider.RefusedError
	_, err = f.client.Register(ctx, walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &reg.leafKey.PublicKey, Evidence: evidence})
	if !errors.As(err, &refused) || refused.Code != "evidence_rejected" {
		t.Fatalf("Register under a renamed Kind = %v, want evidence_rejected", err)
	}
}

// TestRecheck_RenamedKindFailsClosed: an instance of another Kind than
// EvidenceKind, as one registered before Verify refused that, fails the
// adapter's rechecks closed, as a misconfiguration the provider answers
// as its own failure, rather than accepting every instance unjudged: no
// Wallet Attestation is issued, and the instance isn't refused as if
// its evidence were at fault.
func TestRecheck_RenamedKindFailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := newAttestationCA(t)
	v := &androidkey.Verifier{Roots: []*x509.Certificate{ca.root}, Revocation: &androidkey.StatusList{}, Apps: []androidkey.AllowedApp{testApp}}
	ev := renamedAndroid{androidkey.EvidenceVerifier{Verifier: v}}
	f := newProviderFixture(t, ev.EvidenceVerifier)

	ch, raw := f.challenge(t, walletprovider.PurposeRegistration)
	reg := ca.chain(t, 101, raw)
	id, err := f.client.Register(ctx, walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &reg.leafKey.PublicKey, Evidence: androidkey.Evidence(reg.der)})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	// The instance as a renamed adapter would have registered it.
	in, err := f.instances.Get(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	in.Evidence.Kind = ev.Kind()
	if err := f.instances.Update(ctx, in); err != nil {
		t.Fatal(err)
	}
	f.e = ev
	f.serve(t, 42)

	ch, raw = f.challenge(t, walletprovider.PurposeInstance)
	ik := ca.chain(t, 201, raw)
	_, err = f.client.WalletAttestation(ctx, reg.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: id, ClientID: "wallet", InstanceKey: &ik.leafKey.PublicKey, Challenge: ch,
		Evidence: walletprovider.Evidence{Kind: ev.Kind(), Data: slices.Concat(ik.der...)},
	})
	var refused *walletprovider.RefusedError
	if !errors.As(err, &refused) || refused.Status != http.StatusInternalServerError {
		t.Fatalf("Wallet Attestation under a renamed Kind = %v, want the provider's own failure", err)
	}
	if n := len(f.refusals()); n != 0 {
		t.Fatalf("OnRecheckRefused called %d times, want none", n)
	}
	if state := f.state(t, id); state != walletprovider.StateActive {
		t.Fatalf("the instance is %s, want active", state)
	}
}
