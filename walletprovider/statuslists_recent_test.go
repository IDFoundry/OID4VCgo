package walletprovider_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// recentShare is how many indices a period of recentShareLists' lists
// leaves the keys of recent instances: the first
// DefaultRecentInstanceStatusLists lists, of four each.
const recentShare = walletprovider.DefaultRecentInstanceStatusLists * 8 / 2

// recentShareLists gives a period's lists 256 indices between them, a
// quarter of them for recently registered instances, and each instance
// fullListsPerInstance of them.
func recentShareLists(cfg *walletprovider.Config, _ *walletprovider.Dependencies) {
	cfg.StatusListSize = 8 // 64 lists × 8/2: 256 indices a period
	cfg.MaxInstanceKeysPerPeriod = fullListsPerInstance
}

// burst registers instances in the current period, each recording up
// to fullListsPerInstance instance keys, until n of them have, and
// returns the keys recorded, by instance, and how many were refused as
// the lists being full.
func burst(t *testing.T, h *harness, n int) (keys map[string][]*ecdsa.PrivateKey, refused int) {
	t.Helper()
	keys = make(map[string][]*ecdsa.PrivateKey)
	for range n {
		in, _ := h.register(kindTEE)
		for range fullListsPerInstance {
			key := newKey(t)
			_, err := h.walletAttestation(in.ID, &key.PublicKey, kindTEE)
			switch {
			case errors.Is(err, statuslist.ErrListsFull):
				refused++
			case err != nil:
				t.Fatalf("a burst instance's key: %v", err)
			default:
				keys[in.ID] = append(keys[in.ID], key)
			}
		}
	}
	return keys, refused
}

// listNumber is the number of the list ref names, in the current
// period, failing the test if it's another period's.
func (h *harness) listNumber(ref statuslist.StatusListRef) int {
	h.t.Helper()
	for n := range walletprovider.MaxStatusListsPerPeriod {
		if ref.URI == listURI(h.periodStart(), n) {
			return n
		}
	}
	h.t.Fatalf("%s isn't a list of the current period", ref.URI)
	return -1
}

// TestRecentInstancesCantFillStatusLists: instances registered in a
// burst, each within MaxInstanceKeysPerPeriod, fill only their share of
// a period's lists, in the period they register in and, moving their
// recorded keys without evidence, in the next; a wallet registered
// before keeps renewing its recorded key and attesting new ones.
func TestRecentInstancesCantFillStatusLists(t *testing.T) {
	h := newHarness(t, recentShareLists)
	victim, _ := h.register(kindTEE)
	victimKey := h.newInstanceKey(victim.ID, kindTEE)
	// Two periods on, the victim is established, and its key's index is
	// older than the previous period's, which a full period's lists
	// wouldn't let it keep.
	h.toNextPeriod()
	h.toNextPeriod()

	// Enough instances to fill every list, were they let.
	capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2
	attacker, refused := burst(t, h, capacity/fullListsPerInstance)
	if taken := capacity - refused; taken != recentShare {
		t.Fatalf("the burst took %d indices, want its share of %d", taken, recentShare)
	}
	fill, err := h.p.StatusListFill(context.Background())
	if err != nil || fill.RecentInstanceFree() != 0 || fill.Free() != capacity-recentShare ||
		fill.RecentInstanceLists != walletprovider.DefaultRecentInstanceStatusLists {
		t.Fatalf("after the burst, fill = %+v (%v): want the recent instances' share full, and only that", fill, err)
	}

	established := func(period string) {
		t.Helper()
		jwt, err := h.walletAttestation(victim.ID, &victimKey.PublicKey, "")
		if err != nil {
			t.Fatalf("%s: the established wallet's renewal = %v", period, err)
		}
		if n := h.listNumber(walletAttestationStatus(t, jwt)); n < establishedList {
			t.Fatalf("%s: the renewal took list %d, one of the recent instances' share", period, n)
		}
		h.newInstanceKey(victim.ID, kindTEE)
	}
	established("the burst's period")

	// The next period: the burst's instances, still recent, move their
	// recorded keys without evidence, into their share alone.
	h.toNextPeriod()
	moved, full := 0, 0
	for id, keys := range attacker {
		for _, k := range keys {
			switch _, err := h.walletAttestation(id, &k.PublicKey, ""); {
			case err == nil:
				moved++
			case errors.Is(err, statuslist.ErrListsFull):
				full++
			default:
				t.Fatalf("a burst instance's move: %v", err)
			}
		}
	}
	if moved != recentShare {
		t.Fatalf("the burst's instances moved %d keys (%d refused), want their share of %d", moved, full, recentShare)
	}
	established("the next period")
}

// TestRecentInstanceShareFull: once the recent instances' share of a
// period's lists is full, a recent instance's new instance key is
// refused as the lists being full, logged as the share, without the
// instance being suspended or revoked or its quota used; its recorded
// key on the previous period's list keeps its index there; and an
// established instance still gets new indices.
func TestRecentInstanceShareFull(t *testing.T) {
	var log bytes.Buffer
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		recentShareLists(c, d)
		d.Logger = slog.New(slog.NewTextHandler(&log, nil))
	})
	old, _ := h.register(kindTEE)
	h.toNextPeriod()
	h.toNextPeriod()
	recent, _ := h.register(kindTEE)
	recentKey := h.newInstanceKey(recent.ID, kindTEE)
	recorded := h.instanceKey(&recentKey.PublicKey)

	// The next period: the recent instance is still recent, and others
	// registered in this one fill the share.
	h.toNextPeriod()
	if _, refused := burst(t, h, recentShare/fullListsPerInstance); refused != 0 {
		t.Fatalf("%d of the share's indices refused", refused)
	}

	_, err := h.walletAttestation(recent.ID, &newKey(t).PublicKey, kindTEE)
	if !errors.Is(err, statuslist.ErrListsFull) || !strings.Contains(err.Error(), "Config.RecentInstanceStatusLists") {
		t.Fatalf("a recent instance's new key with its share full = %v, want the share full", err)
	}
	if !strings.Contains(log.String(), "recently registered instances take indices from are full") {
		t.Fatalf("the refusal isn't logged as the recent instances' share:\n%s", log.String())
	}
	in, err := h.deps.Instances.Get(context.Background(), recent.ID)
	if err != nil || in.State != walletprovider.StateActive || in.IndicesInPeriod != 0 {
		t.Fatalf("after the refusal, the instance is %+v (%v); want it active, its quota unused", in, err)
	}
	jwt, err := h.walletAttestation(recent.ID, &recentKey.PublicKey, "")
	if err != nil {
		t.Fatalf("a recent instance's recorded key with its share full = %v", err)
	}
	if ref := walletAttestationStatus(t, jwt); ref != recorded.Status {
		t.Fatalf("the renewal names %+v, want the previous period's %+v", ref, recorded.Status)
	}

	key := h.newInstanceKey(old.ID, kindTEE)
	if n := h.listNumber(h.instanceKey(&key.PublicKey).Status); n < establishedList {
		t.Fatalf("an established instance's key took list %d, of the recent instances' share", n)
	}
}

// TestEstablishedTakeRecentShareLast: an established instance's keys
// take indices from the recent instances' share only once the other
// lists are full.
func TestEstablishedTakeRecentShareLast(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		recentShareLists(c, d)
		c.MaxInstanceKeysPerPeriod = 1000
	})
	in, _ := h.register(kindTEE)
	h.toNextPeriod()
	h.toNextPeriod()
	capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2
	for i := range capacity {
		key := h.newInstanceKey(in.ID, kindTEE)
		n := h.listNumber(h.instanceKey(&key.PublicKey).Status)
		if want := i < capacity-recentShare; want != (n >= establishedList) {
			t.Fatalf("established key %d took list %d", i, n)
		}
	}
	if _, err := h.walletAttestation(in.ID, &newKey(t).PublicKey, kindTEE); !errors.Is(err, statuslist.ErrListsFull) ||
		!strings.Contains(err.Error(), "the status lists of the current period are full") {
		t.Fatalf("an established key past every list = %v, want them full", err)
	}
}

// TestInstanceAgesOutOfRecent: an instance's keys take indices from
// the recent instances' share in the period it registers in and the
// next, and from the other lists from the period after.
func TestInstanceAgesOutOfRecent(t *testing.T) {
	h := newHarness(t, nil)
	in, _ := h.register(kindStrongBox)
	for period, want := range []int{0, 0, establishedList, establishedList} {
		if period > 0 {
			h.toNextPeriod()
		}
		key := h.newInstanceKey(in.ID, kindStrongBox)
		if n := h.listNumber(h.instanceKey(&key.PublicKey).Status); n != want {
			t.Fatalf("%d periods after registering, a key took list %d, want %d", period, n, want)
		}
	}
}

// TestRecentInstanceShareOff: RecentInstanceStatusLists set to
// MaxStatusListsPerPeriod lets recent instances take indices from every
// list, as before the share.
func TestRecentInstanceShareOff(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		recentShareLists(c, d)
		c.RecentInstanceStatusLists = walletprovider.MaxStatusListsPerPeriod
	})
	capacity := walletprovider.MaxStatusListsPerPeriod * 8 / 2
	if _, refused := burst(t, h, capacity/fullListsPerInstance); refused != 0 {
		t.Fatalf("%d of a burst's keys refused with the share off", refused)
	}
	fill, err := h.p.StatusListFill(context.Background())
	if err != nil || fill.Free() != 0 || fill.RecentInstanceFree() != 0 {
		t.Fatalf("fill = %+v, %v; want every list full", fill, err)
	}
	in, _ := h.register(kindTEE)
	_, err = h.walletAttestation(in.ID, &newKey(t).PublicKey, kindTEE)
	if !errors.Is(err, statuslist.ErrListsFull) || strings.Contains(err.Error(), "RecentInstanceStatusLists") {
		t.Fatalf("a key past every list with the share off = %v, want the lists full", err)
	}
}

// TestEstablishedSpreadOverEveryList: an established instance's keys
// take indices on the recent instances' share in proportion to its
// size, so those lists don't hold recent instances' keys alone; and
// when the share chosen is full, the other lists take the key.
func TestEstablishedSpreadOverEveryList(t *testing.T) {
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		c.MaxInstanceKeysPerPeriod = 1000
		d.Random = rand.Reader
	})
	in, _ := h.register(kindTEE)
	h.toNextPeriod()
	h.toNextPeriod()
	inShare := 0
	const keys = 400
	for range keys {
		key := h.newInstanceKey(in.ID, kindTEE)
		if h.listNumber(h.instanceKey(&key.PublicKey).Status) < establishedList {
			inShare++
		}
	}
	// Expected keys/4 = 100; far outside 40-160 is a broken choice.
	if inShare < 40 || inShare > 160 {
		t.Fatalf("%d of %d established keys took the recent instances' share, want about a quarter", inShare, keys)
	}
}
