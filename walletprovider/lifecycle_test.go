package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// expectStatus checks the instance's status in both forms of the
// published list.
func (h *harness) expectStatus(in walletprovider.Instance, want statuslist.StatusType) {
	h.t.Helper()
	for _, cwt := range []bool{false, true} {
		if got := h.status(in.Status, cwt); got != want {
			h.t.Fatalf("published status (cwt %t) = %v, want %v", cwt, got, want)
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

func TestSuspendResumeRevoke(t *testing.T) {
	h := newHarness(t, nil)
	in, key := h.register(kindStrongBox)
	other, _ := h.register(kindStrongBox)
	ctx := context.Background()
	h.expectStatus(in, statuslist.StatusValid)

	if err := h.p.Suspend(ctx, in.ID, "reported lost"); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateSuspended, "reported lost")
	h.expectStatus(in, statuslist.StatusSuspended)
	h.expectStatus(other, statuslist.StatusValid)
	if _, err := h.walletAttestation(in.ID); !errors.Is(err, walletprovider.ErrInstanceNotActive) || errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("WalletAttestation while suspended = %v, want ErrInstanceNotActive", err)
	}
	if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
		t.Fatalf("KeyAttestation while suspended = %v, want ErrInstanceNotActive", err)
	}

	if err := h.p.Resume(ctx, in.ID); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateActive, "")
	h.expectStatus(in, statuslist.StatusValid)
	if _, err := h.walletAttestation(in.ID); err != nil {
		t.Fatalf("WalletAttestation after resuming: %v", err)
	}

	if err := h.p.Revoke(ctx, in.ID, "compromised"); err != nil {
		t.Fatal(err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "compromised")
	h.expectStatus(in, statuslist.StatusInvalid)
	h.expectStatus(other, statuslist.StatusValid)
	if _, err := h.walletAttestation(in.ID); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
		t.Fatalf("WalletAttestation once revoked = %v, want ErrInstanceRevoked", err)
	}
	if _, err := h.keyAttestation(in.ID, []*ecdsa.PrivateKey{key}, kindStrongBox); !errors.Is(err, walletprovider.ErrInstanceRevoked) {
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
	h.expectStatus(in, statuslist.StatusInvalid)

	if err := h.p.Revoke(ctx, "nope", "x"); !errors.Is(err, walletprovider.ErrInstanceNotFound) {
		t.Fatalf("Revoke(unknown) = %v, want ErrInstanceNotFound", err)
	}
}

func TestRevokeWhere(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) { c.StatusListSize = 4096 })
	var tee, strongBox []walletprovider.Instance
	for range 120 {
		in, _ := h.register(kindTEE)
		tee = append(tee, in)
	}
	for range 3 {
		in, _ := h.register(kindStrongBox)
		strongBox = append(strongBox, in)
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
	h.expectStatus(tee[len(tee)-1], statuslist.StatusInvalid)
	for _, in := range strongBox {
		h.expectState(in.ID, walletprovider.StateActive, "")
		h.expectStatus(in, statuslist.StatusValid)
	}
	if _, err := h.p.RevokeWhere(context.Background(), nil, "x"); err == nil {
		t.Fatal("RevokeWhere(nil) succeeded")
	}
}
