package androidkey_test

import (
	"context"
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

// TestRecheck_RenamedKindFailsClosed: served under another Kind than
// EvidenceKind, the adapter's rechecks fail closed, as a
// misconfiguration the provider answers as its own failure, rather than
// accepting every instance unjudged: no Wallet Attestation is issued,
// and the instance isn't refused as if its evidence were at fault.
func TestRecheck_RenamedKindFailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := newAttestationCA(t)
	v := &androidkey.Verifier{Roots: []*x509.Certificate{ca.root}, Revocation: &androidkey.StatusList{}, Apps: []androidkey.AllowedApp{testApp}}
	ev := renamedAndroid{androidkey.EvidenceVerifier{Verifier: v}}
	f := newProviderFixture(t, ev)
	evidence := func(c testChain) walletprovider.Evidence {
		return walletprovider.Evidence{Kind: ev.Kind(), Data: slices.Concat(c.der...)}
	}

	ch, raw := f.challenge(t, walletprovider.PurposeRegistration)
	reg := ca.chain(t, 101, raw)
	id, err := f.client.Register(ctx, walletprovider.RegisterRequest{Challenge: ch, RegistrationKey: &reg.leafKey.PublicKey, Evidence: evidence(reg)})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	ch, raw = f.challenge(t, walletprovider.PurposeInstance)
	ik := ca.chain(t, 201, raw)
	_, err = f.client.WalletAttestation(ctx, reg.leafKey, walletprovider.WalletAttestationRequest{
		InstanceID: id, ClientID: "wallet", InstanceKey: &ik.leafKey.PublicKey, Challenge: ch, Evidence: evidence(ik),
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
