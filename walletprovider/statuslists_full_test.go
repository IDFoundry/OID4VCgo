package walletprovider_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// fullListsPerInstance is smallStatusLists' MaxInstanceKeysPerPeriod.
const fullListsPerInstance = 4

// smallStatusLists gives a period's lists 256 indices between them, and
// each instance fullListsPerInstance of them.
func smallStatusLists(cfg *walletprovider.Config, _ *walletprovider.Dependencies) {
	cfg.StatusListSize = 8 // 64 lists × 8/2: 256 indices a period
	cfg.MaxInstanceKeysPerPeriod = fullListsPerInstance
}

// fillStatusLists fills the current period's lists of a
// smallStatusLists harness with new instances, each within its quota.
func fillStatusLists(t *testing.T, h *harness) {
	t.Helper()
	capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2
	for range capacity / fullListsPerInstance {
		in, _ := h.register(kindTEE)
		for range fullListsPerInstance {
			h.newInstanceKey(in.ID, kindTEE)
		}
	}
	fill, err := h.p.StatusListFill(context.Background())
	if err != nil || fill.Free() != 0 {
		t.Fatalf("StatusListFill = %d free, %v; want the lists full", fill.Free(), err)
	}
}

// TestStatusListsFullKeepPreviousIndex: once many instances, each
// within MaxInstanceKeysPerPeriod, fill a period's lists between them,
// a recorded instance key last used in the previous period still gets
// its Wallet Attestation, naming its previous period's index, which a
// revocation still reaches; a new instance key is refused until the
// next period.
func TestStatusListsFullKeepPreviousIndex(t *testing.T) {
	h := newHarness(t, smallStatusLists)
	victim, _ := h.register(kindTEE)
	victimKey := h.newInstanceKey(victim.ID, kindTEE)
	recorded := h.instanceKey(&victimKey.PublicKey)

	// The next period: instances each within their quota fill its lists.
	h.toNextPeriod()
	fillStatusLists(t, h)

	jwt, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, "")
	if err != nil {
		t.Fatalf("a recorded key's renewal with the lists full = %v", err)
	}
	if ref := walletAttestationStatus(t, jwt); ref != recorded.Status {
		t.Fatalf("the renewal names %+v, want the previous period's %+v", ref, recorded.Status)
	}
	if kept := h.instanceKey(&victimKey.PublicKey); kept.Status != recorded.Status || kept.Revision != recorded.Revision {
		t.Fatalf("the record moved: %+v", kept)
	}

	fresh, _ := h.register(kindTEE)
	if _, err := h.walletAttestation(fresh.ID, &newKey(t).PublicKey, kindTEE); !errors.Is(err, statuslist.ErrListsFull) {
		t.Fatalf("a new instance key with the lists full = %v, want ErrListsFull", err)
	}

	if err := h.p.Revoke(context.Background(), victim.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	h.expectStatus(statuslist.StatusInvalid, victimKey)
}

// TestStatusListsFullKeptIndexRevokedAfterMove: a recorded key that
// kept its previous period's index through a full period, then moves
// in the next, keeps that index as its PreviousStatus, so a revocation
// still reaches a live attestation issued late in the full period.
func TestStatusListsFullKeptIndexRevokedAfterMove(t *testing.T) {
	h := newHarness(t, smallStatusLists)
	victim, _ := h.register(kindTEE)
	victimKey := h.newInstanceKey(victim.ID, kindTEE)
	kept := h.instanceKey(&victimKey.PublicKey).Status

	// The next period's lists fill early; half an hour before it ends,
	// the key renews on its kept index.
	h.toNextPeriod()
	fillStatusLists(t, h)
	h.clock.advance(time.Unix(h.periodStart(), 0).Add(h.period() - 30*time.Minute).Sub(h.clock.now()))
	jwt, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if named := walletAttestationStatus(t, jwt); named != kept {
		t.Fatalf("the late renewal names %+v, want the kept %+v", named, kept)
	}
	expires := h.clock.now().Add(walletprovider.DefaultWalletAttestationTTL)

	// In the period after, the key moves, and the instance is revoked
	// while the late attestation is live.
	h.toNextPeriod()
	if _, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, ""); err != nil {
		t.Fatal(err)
	}
	if moved := h.instanceKey(&victimKey.PublicKey); moved.PreviousStatus != kept {
		t.Fatalf("PreviousStatus after the move = %+v, want the kept %+v", moved.PreviousStatus, kept)
	}
	if err := h.p.Revoke(context.Background(), victim.ID, "stolen"); err != nil {
		t.Fatal(err)
	}
	if !h.clock.now().Before(expires) {
		t.Fatal("the late attestation has expired: the test needs it live")
	}
	if got := h.status(kept, false); got != statuslist.StatusInvalid {
		t.Fatalf("the late attestation's status after the revocation = %v, want INVALID", got)
	}
}
