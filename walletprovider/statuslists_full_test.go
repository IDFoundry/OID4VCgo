package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// fullListsPerInstance is smallStatusLists' MaxInstanceKeysPerPeriod.
const fullListsPerInstance = 4

// smallStatusLists gives a period's lists 256 indices between them, and
// each instance fullListsPerInstance of them. Recent instances take
// indices from every list, so new ones can fill them.
func smallStatusLists(cfg *walletprovider.Config, _ *walletprovider.Dependencies) {
	cfg.StatusListSize = 8 // 64 lists × 8/2: 256 indices a period
	cfg.MaxInstanceKeysPerPeriod = fullListsPerInstance
	cfg.RecentInstanceStatusLists = walletprovider.MaxStatusListsPerPeriod
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

// TestStatusListsFullRenewalsKeepQuota: a recorded key's renewal while
// the period's lists are full takes no index, so it doesn't count
// against MaxInstanceKeysPerPeriod: the key renews more often than
// that, and the instance's count stays as it was.
func TestStatusListsFullRenewalsKeepQuota(t *testing.T) {
	h := newHarness(t, smallStatusLists)
	victim, _ := h.register(kindTEE)
	victimKey := h.newInstanceKey(victim.ID, kindTEE)

	h.toNextPeriod()
	fillStatusLists(t, h)
	for i := range 2 * fullListsPerInstance {
		if _, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, ""); err != nil {
			t.Fatalf("renewal %d with the lists full = %v", i+1, err)
		}
	}
	in, err := h.deps.Instances.Get(context.Background(), victim.ID)
	if err != nil || in.IndicesInPeriod != 0 {
		t.Fatalf("the instance counts %d indices (%v) after the renewals, want 0", in.IndicesInPeriod, err)
	}
}

// TestStatusListsFullQuotaUsedKeepsPreviousIndex: an instance that has
// used up its MaxInstanceKeysPerPeriod still renews a recorded key on
// the previous period's list once the lists its keys take indices from
// are full, keeping that index, as the renewal takes none of the
// quota: for an established instance, every list; for a recent one,
// its share, the other lists still with room.
func TestStatusListsFullQuotaUsedKeepsPreviousIndex(t *testing.T) {
	ctx := context.Background()
	renew := func(t *testing.T, h *harness, id string, key *ecdsa.PrivateKey) {
		t.Helper()
		kept := h.instanceKey(&key.PublicKey).Status
		jwt, err := h.walletAttestation(id, &key.PublicKey, "")
		if err != nil {
			t.Fatalf("the renewal with the lists full and the quota used = %v", err)
		}
		if ref := walletAttestationStatus(t, jwt); ref != kept {
			t.Fatalf("the renewal names %+v, want the previous period's %+v", ref, kept)
		}
		in, err := h.deps.Instances.Get(ctx, id)
		if err != nil || in.IndicesInPeriod != fullListsPerInstance {
			t.Fatalf("the instance counts %d indices (%v), want its %d", in.IndicesInPeriod, err, fullListsPerInstance)
		}
	}

	t.Run("established", func(t *testing.T) {
		h := newHarness(t, recentShareLists)
		victim, _ := h.register(kindTEE)
		victimKey := h.newInstanceKey(victim.ID, kindTEE)
		capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2
		var fleet []string
		for range capacity / fullListsPerInstance {
			in, _ := h.register(kindTEE)
			fleet = append(fleet, in.ID)
		}
		h.toNextPeriod()
		if _, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, ""); err != nil {
			t.Fatal(err)
		}
		// Two periods on, every instance is established: the victim uses
		// up its quota, then the fleet fills every list.
		h.toNextPeriod()
		for range fullListsPerInstance {
			h.newInstanceKey(victim.ID, kindTEE)
		}
		for _, id := range fleet {
			for range fullListsPerInstance {
				if _, err := h.walletAttestation(id, &newKey(t).PublicKey, kindTEE); err != nil && !errors.Is(err, statuslist.ErrListsFull) {
					t.Fatal(err)
				}
			}
		}
		if fill, err := h.p.StatusListFill(ctx); err != nil || fill.Free() != 0 {
			t.Fatalf("StatusListFill = %d free, %v; want the lists full", fill.Free(), err)
		}
		renew(t, h, victim.ID, victimKey)
	})

	t.Run("recent", func(t *testing.T) {
		h := newHarness(t, recentShareLists)
		h.toNextPeriod()
		victim, _ := h.register(kindTEE)
		victimKey := h.newInstanceKey(victim.ID, kindTEE)
		// The next period: the victim, still recent, uses up its quota,
		// then instances registered in it fill the rest of the share.
		h.toNextPeriod()
		for range fullListsPerInstance {
			h.newInstanceKey(victim.ID, kindTEE)
		}
		if _, refused := burst(t, h, recentShare/fullListsPerInstance-1); refused != 0 {
			t.Fatalf("%d of the share's indices refused", refused)
		}
		if fill, err := h.p.StatusListFill(ctx); err != nil || fill.RecentInstanceFree() != 0 || fill.Free() == 0 {
			t.Fatalf("StatusListFill = %+v, %v; want the share full, and only it", fill, err)
		}
		renew(t, h, victim.ID, victimKey)
	})
}

// TestStatusListsFullRecorded: a process that finds the lists full
// records it, so its next request for an index doesn't count their
// reserved indices again.
func TestStatusListsFullRecorded(t *testing.T) {
	idx := &countingIndices{}
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		smallStatusLists(c, d)
		d.StatusIndices = idx
	})
	fillStatusLists(t, h)
	// A fresh process facing the full lists.
	p, err := walletprovider.New(h.cfg, h.deps)
	if err != nil {
		t.Fatal(err)
	}
	h.p = p
	in, _ := h.register(kindTEE)
	for i := range 2 {
		before := idx.calls()
		if _, err := h.walletAttestation(in.ID, &newKey(t).PublicKey, kindTEE); !errors.Is(err, statuslist.ErrListsFull) {
			t.Fatalf("attempt %d: a new instance key with the lists full = %v, want ErrListsFull", i+1, err)
		}
		if counted := idx.calls() - before; i > 0 && counted != 0 {
			t.Fatalf("attempt %d counted the reserved indices of %d lists, known full", i+1, counted)
		}
	}
}
