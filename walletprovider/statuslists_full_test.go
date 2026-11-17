package walletprovider_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// TestStatusListsFullKeepPreviousIndex: once many instances, each
// within MaxInstanceKeysPerPeriod, fill a period's lists between them,
// a recorded instance key last used in the previous period still gets
// its Wallet Attestation, naming its previous period's index, which a
// revocation still reaches; a new instance key is refused until the
// next period.
func TestStatusListsFullKeepPreviousIndex(t *testing.T) {
	const perInstance = 4
	h := newHarness(t, func(cfg *walletprovider.Config, _ *walletprovider.Dependencies) {
		cfg.StatusListSize = 8 // 64 lists × 8/2: 256 indices a period
		cfg.MaxInstanceKeysPerPeriod = perInstance
	})
	capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2

	victim, _ := h.register(kindTEE)
	victimKey := h.newInstanceKey(victim.ID, kindTEE)
	recorded := h.instanceKey(&victimKey.PublicKey)

	// The next period: instances each within their quota fill its lists.
	h.toNextPeriod()
	for range capacity / perInstance {
		in, _ := h.register(kindTEE)
		for range perInstance {
			h.newInstanceKey(in.ID, kindTEE)
		}
	}
	fill, err := h.p.StatusListFill(context.Background())
	if err != nil || fill.Free() != 0 {
		t.Fatalf("StatusListFill = %d free, %v; want the lists full", fill.Free(), err)
	}

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
