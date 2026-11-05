package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// expectStatus checks the status of each of the instance keys keys in
// both forms of the published list.
func (h *harness) expectStatus(want statuslist.StatusType, keys ...*ecdsa.PrivateKey) {
	h.t.Helper()
	for _, k := range keys {
		ref := h.instanceKey(&k.PublicKey).Status
		for _, cwt := range []bool{false, true} {
			if got := h.status(ref, cwt); got != want {
				h.t.Fatalf("published status of %+v (cwt %t) = %v, want %v", ref, cwt, got, want)
			}
		}
	}
}

func (h *harness) expectState(id string, state walletprovider.State, reason string) {
	h.t.Helper()
	in, err := h.deps.Instances.Get(context.Background(), id)
	if err != nil {
		h.t.Fatal(err)
	}
	if in.State != state || in.Reason != reason {
		h.t.Fatalf("instance is %s (%q), want %s (%q)", in.State, in.Reason, state, reason)
	}
}

// TestSuspendResumeRevoke: suspending, resuming and revoking an
// instance sets the status of every one of its instance keys, and of
// no other instance's.
func TestSuspendResumeRevoke(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	keys := []*ecdsa.PrivateKey{h.newInstanceKey(in.ID, kindStrongBox), h.newInstanceKey(in.ID, kindTEE)}
	other, _ := h.register(kindStrongBox)
	othersKey := h.newInstanceKey(other.ID, kindStrongBox)
	ctx := context.Background()
	h.expectStatus(statuslist.StatusValid, keys...)

	if err := h.p.Suspend(ctx, in.ID, "reported lost"); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateSuspended, "reported lost")
	h.expectStatus(statuslist.StatusSuspended, keys...)
	h.expectStatus(statuslist.StatusValid, othersKey)
	if _, err := h.walletAttestation(in.ID, &keys[0].PublicKey, ""); !errors.Is(err, walletprovider.ErrInstanceNotActive) || errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("WalletAttestation while suspended = %v, want ErrInstanceNotActive", err)
	}
	if _, err := h.keyAttestation(in.ID, &keys[0].PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
		t.Fatalf("KeyAttestation while suspended = %v, want ErrInstanceNotActive", err)
	}
	// Nor does a suspended instance get a new instance key recorded.
	fresh := newKey(t)
	if _, err := h.walletAttestation(in.ID, &fresh.PublicKey, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
		t.Fatalf("WalletAttestation for a new key while suspended = %v, want ErrInstanceNotActive", err)
	}
	if _, err := h.deps.InstanceKeys.Get(ctx, h.thumbprint(&fresh.PublicKey)); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("a suspended instance's new key was recorded: %v", err)
	}

	if err := h.p.Resume(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateActive, "")
	h.expectStatus(statuslist.StatusValid, keys...)
	if _, err := h.walletAttestation(in.ID, &keys[1].PublicKey, ""); err != nil {
		t.Fatalf("WalletAttestation after resuming: %v", err)
	}

	if err := h.p.Revoke(ctx, in.ID, "compromised"); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "compromised")
	h.expectStatus(statuslist.StatusInvalid, keys...)
	h.expectStatus(statuslist.StatusValid, othersKey)
	if _, err := h.walletAttestation(in.ID, &keys[0].PublicKey, ""); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("WalletAttestation once revoked = %v, want ErrInstanceRevoked", err)
	}
	if _, err := h.keyAttestation(in.ID, &keys[0].PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("KeyAttestation once revoked = %v, want ErrInstanceRevoked", err)
	}

	// Revocation is final.
	if err := h.p.Resume(ctx, in.ID); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("Resume once revoked = %v, want ErrInstanceRevoked", err)
	}
	if err := h.p.Suspend(ctx, in.ID, "again"); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("Suspend once revoked = %v, want ErrInstanceRevoked", err)
	}
	if err := h.p.Revoke(ctx, in.ID, "twice"); err != nil {
		t.Fatalf("revoking again: %v", err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "compromised")
	h.expectStatus(statuslist.StatusInvalid, keys...)

	if err := h.p.Revoke(ctx, "nope", "x"); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("Revoke(unknown) = %v, want ErrInstanceNotFound", err)
	}
}

// TestTransitionSetsEveryKey: an instance with more instance keys than
// one page of the store has every one's status set.
func TestTransitionSetsEveryKey(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.StatusListSize = 1024 })
	in, _ := h.register(kindStrongBox)
	var keys []*ecdsa.PrivateKey
	for range 105 {
		keys = append(keys, h.newInstanceKey(in.ID, kindStrongBox))
	}
	if err := h.p.Revoke(context.Background(), in.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	h.expectStatus(statuslist.StatusInvalid, keys...)
}

func TestRevokeWhere(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.StatusListSize = 4096 })
	var tee, strongBox []walletprovider.Instance
	var teeKey *ecdsa.PrivateKey
	var strongBoxKeys []*ecdsa.PrivateKey
	for range 120 {
		in, _ := h.register(kindTEE)
		tee = append(tee, in)
	}
	teeKey = h.newInstanceKey(tee[len(tee)-1].ID, kindTEE)
	for range 3 {
		in, _ := h.register(kindStrongBox)
		strongBox = append(strongBox, in)
		strongBoxKeys = append(strongBoxKeys, h.newInstanceKey(in.ID, kindStrongBox))
	}
	if err := h.p.Revoke(context.Background(), tee[0].ID, "earlier"); err != nil {
		t.Fatal(err)
	}
	n, err := h.p.RevokeWhere(context.Background(), func(in walletprovider.Instance) bool {
		return in.Evidence.SecurityLevel == walletprovider.SecurityLevelTEE
	}, "TEE firmware flaw")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(tee)-1 {
		t.Fatalf("RevokeWhere revoked %d, want %d", n, len(tee)-1)
	}
	h.expectState(tee[0].ID, walletprovider.StateRevoked, "earlier")
	for _, in := range tee[1:] {
		h.expectState(in.ID, walletprovider.StateRevoked, "TEE firmware flaw")
	}
	h.expectStatus(statuslist.StatusInvalid, teeKey)
	for _, in := range strongBox {
		h.expectState(in.ID, walletprovider.StateActive, "")
	}
	h.expectStatus(statuslist.StatusValid, strongBoxKeys...)
	if _, err := h.p.RevokeWhere(context.Background(), nil, "x"); err == nil {
		t.Fatal("RevokeWhere(nil) succeeded")
	}
}
