package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// withRetention sets the shortest StatusListPeriod, as withPeriod
// does, and the shortest InstanceKeyRetention for it: three periods.
func withRetention(c *walletprovider.Config, d *walletprovider.Dependencies) {
	withPeriod(c, d)
	c.InstanceKeyRetention = 3 * c.StatusListPeriod
}

// TestInstanceKeyRetentionDefault: zero InstanceKeyRetention is
// DefaultInstanceKeyRetention, or three StatusListPeriods when they're
// longer, and a key's RetainUntil is its period's start plus it.
func TestInstanceKeyRetentionDefault(t *testing.T) {
	day := 24 * time.Hour
	for _, tc := range []struct {
		name              string
		period, retention time.Duration
		want              time.Duration
	}{
		{"default period", 0, 0, walletprovider.DefaultInstanceKeyRetention},
		{"long period", 60 * day, 0, 180 * day},
		{"set", 0, 400 * day, 400 * day},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, func(c *walletprovider.Config, _ *walletprovider.Dependencies) {
				c.StatusListPeriod, c.InstanceKeyRetention = tc.period, tc.retention
			})
			in, _ := h.register(kindStrongBox)
			key := h.newInstanceKey(in.ID, kindStrongBox)
			if got, want := h.instanceKey(&key.PublicKey).RetainUntil, time.Unix(h.periodStart(), 0).Add(tc.want); !got.Equal(want) {
				t.Fatalf("RetainUntil = %v, want %v", got, want)
			}
		})
	}
}

// TestRetainUntilFollowsUse: recording an instance key sets its
// RetainUntil from the current period's start, a use within the period
// leaves it, and moving the key to a later period's lists sets it from
// that period's start.
func TestRetainUntilFollowsUse(t *testing.T) {
	h := newHarness(t, withRetention)
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	expect := func(what string) {
		t.Helper()
		if got, want := h.instanceKey(&key.PublicKey).RetainUntil, time.Unix(h.periodStart(), 0).Add(3*h.period()); !got.Equal(want) {
			t.Fatalf("%s: RetainUntil = %v, want %v", what, got, want)
		}
	}
	expect("recorded")
	h.clock.advance(time.Minute)
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err != nil {
		t.Fatal(err)
	}
	expect("used within the period")
	h.toNextPeriod()
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err != nil {
		t.Fatal(err)
	}
	expect("moved by a Wallet Attestation")
	h.toNextPeriod()
	if _, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); err != nil {
		t.Fatal(err)
	}
	expect("moved by a Key Attestation")
}

// TestMemoryInstanceKeyStoreDropsExpired: Create drops the records
// whose RetainUntil is before the new one's CreatedAt, and keeps those
// with none.
func TestMemoryInstanceKeyStoreDropsExpired(t *testing.T) {
	ctx := context.Background()
	s := &walletprovider.MemoryInstanceKeyStore{}
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	for tp, retain := range map[string]time.Time{"expired": at, "unset": {}, "live": at.Add(2 * time.Hour)} {
		if err := s.Create(ctx, walletprovider.InstanceKey{Thumbprint: tp, InstanceID: "a", CreatedAt: at.Add(-time.Hour), RetainUntil: retain}); err != nil {
			t.Fatal(err)
		}
	}
	// Enough records that a Create sweeps.
	for i := range 64 {
		k := walletprovider.InstanceKey{Thumbprint: fmt.Sprintf("new-%02d", i), InstanceID: "a", CreatedAt: at.Add(time.Hour), RetainUntil: at.Add(time.Hour)}
		if err := s.Create(ctx, k); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Get(ctx, "expired"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get(an expired record) = %v, want ErrNotFound", err)
	}
	for _, tp := range []string{"unset", "live", "new-00"} {
		if _, err := s.Get(ctx, tp); err != nil {
			t.Fatalf("Get(%q): %v", tp, err)
		}
	}
}

// TestDeletedInstanceKeyIsNew: once the store has deleted an instance
// key's record, after its RetainUntil, a Key Attestation naming the key
// is refused as for an unknown key, and a Wallet Attestation for it
// needs evidence, which records the key afresh.
func TestDeletedInstanceKeyIsNew(t *testing.T) {
	h := newHarness(t, withRetention)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	old := h.instanceKey(&key.PublicKey)
	for range 3 {
		h.toNextPeriod()
	}
	if !h.clock.now().After(old.RetainUntil) {
		t.Fatalf("now %v isn't past RetainUntil %v", h.clock.now(), old.RetainUntil)
	}
	// The memory store drops expired records as it records enough new
	// ones.
	for range 64 {
		h.newInstanceKey(in.ID, kindStrongBox)
	}
	if _, err := h.deps.InstanceKeys.Get(ctx, h.thumbprint(&key.PublicKey)); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get(the expired key) = %v, want ErrNotFound", err)
	}

	if _, err := h.keyAttestation(in.ID, &key.PublicKey, []*ecdsa.PrivateKey{newKey(t)}, kindStrongBox); !errors.Is(err, walletprovider.ErrUnknownInstanceKey) {
		t.Fatalf("a Key Attestation naming a deleted key = %v, want ErrUnknownInstanceKey", err)
	}
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrEvidenceRequired) {
		t.Fatalf("a Wallet Attestation for a deleted key without evidence = %v, want ErrEvidenceRequired", err)
	}
	jwt, err := h.walletAttestation(in.ID, &key.PublicKey, kindStrongBox)
	if err != nil {
		t.Fatalf("a Wallet Attestation for a deleted key with evidence: %v", err)
	}
	again := h.instanceKey(&key.PublicKey)
	if again.Revision != 1 || again.Status.URI != listURI(h.periodStart(), 0) || again.Status == old.Status ||
		again.PreviousStatus != (statuslist.StatusListRef{}) || !again.RetainUntil.Equal(time.Unix(h.periodStart(), 0).Add(3*h.period())) {
		t.Fatalf("recorded again as %+v; was %+v", again, old)
	}
	if ref := walletAttestationStatus(t, jwt); ref != again.Status {
		t.Fatalf("the Wallet Attestation names %+v, want %+v", ref, again.Status)
	}
}

// reserveOn reserves index 1 of each of lists, on the lists of the
// period starting at start.
func (h *harness) reserveOn(start int64, lists ...int) {
	h.t.Helper()
	for _, n := range lists {
		if err := h.deps.StatusIndices.Reserve(context.Background(), listURI(start, n), 1); err != nil {
			h.t.Fatal(err)
		}
	}
}

// expectReserved checks how many indices the list n of the period
// starting at start has reserved.
func (h *harness) expectReserved(start int64, n, want int) {
	h.t.Helper()
	if got, err := h.deps.StatusIndices.Reserved(context.Background(), listURI(start, n)); err != nil || got != want {
		h.t.Fatalf("Reserved(%s) = %d, %v; want %d", listURI(start, n), got, err, want)
	}
}

// sweep runs SweepStatusLists, expecting it to delete want lists.
func (h *harness) sweep(want int) {
	h.t.Helper()
	if n, err := h.p.SweepStatusLists(context.Background()); err != nil || n != want {
		h.t.Fatalf("SweepStatusLists = %d, %v; want %d", n, err, want)
	}
}

// TestSweepStatusLists: SweepStatusLists deletes every list of the
// periods before those served, walking back until maxEmptyPeriods
// periods in a row have none, and leaves the served ones; run again, it
// finds nothing. A key whose index was on a deleted list moves on its
// next use, and revoking its instance passes the list by.
func TestSweepStatusLists(t *testing.T) {
	h := newHarness(t, withRetention)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	for range 3 {
		h.toNextPeriod()
	}
	cur, p := h.periodStart(), int64(h.period()/time.Second)
	// The key's list is list 0 of the oldest period not served.
	h.reserveOn(cur-3*p, 1, 2)
	h.reserveOn(cur-5*p, 0)
	h.reserveOn(cur-13*p, 0) // after seven empty periods
	h.reserveOn(cur-22*p, 0) // after eight: not reached
	h.reserveOn(cur-2*p, 0)  // served
	h.reserveOn(cur, 0)
	h.reserveOn(cur+p, 0)

	h.sweep(5)
	for _, start := range []int64{cur - 3*p, cur - 5*p, cur - 13*p} {
		h.expectReserved(start, 0, 0)
	}
	h.expectReserved(cur-3*p, 2, 0)
	for _, start := range []int64{cur - 22*p, cur - 2*p, cur, cur + p} {
		h.expectReserved(start, 0, 1)
	}
	h.sweep(0)

	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err != nil {
		t.Fatalf("a Wallet Attestation for a key on a deleted list: %v", err)
	}
	if ik := h.instanceKey(&key.PublicKey); ik.Status.URI != listURI(cur, 0) || ik.PreviousStatus != (statuslist.StatusListRef{}) {
		t.Fatalf("a key on a deleted list moved to %+v", ik)
	}
	if err := h.p.Revoke(ctx, in.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	h.expectStatus(statuslist.StatusInvalid, key)
}

// failingDelete is a MemoryIndexStore whose Delete of uri fails once.
type failingDelete struct {
	statuslist.MemoryIndexStore
	uri    string
	failed bool
}

func (s *failingDelete) Delete(ctx context.Context, uri string) error {
	if uri == s.uri && !s.failed {
		s.failed = true
		return errors.New("the database is down")
	}
	return s.MemoryIndexStore.Delete(ctx, uri)
}

// TestSweepStatusListsResumes: a sweep that fails part-way through a
// period's lists leaves the rest, list 0 among them, for the next one.
func TestSweepStatusListsResumes(t *testing.T) {
	store := &failingDelete{}
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		withRetention(c, d)
		d.StatusIndices = store
	})
	start := h.periodStart() - 3*int64(h.period()/time.Second)
	store.uri = listURI(start, 1)
	h.reserveOn(start, 0, 1, 2)
	if n, err := h.p.SweepStatusLists(context.Background()); err == nil || n != 1 {
		t.Fatalf("SweepStatusLists with a failing Delete = %d, %v; want 1 and an error", n, err)
	}
	h.expectReserved(start, 0, 1)
	h.expectReserved(start, 1, 1)
	h.expectReserved(start, 2, 0)
	h.sweep(2)
	h.expectReserved(start, 0, 0)
	h.expectReserved(start, 1, 0)
}

// sweptOnUpdate is an InstanceKeyStore whose records are swept once
// sweep is set, between a request's read of one and its update.
type sweptOnUpdate struct {
	walletprovider.InstanceKeyStore
	sweep bool
}

func (s *sweptOnUpdate) Update(ctx context.Context, k walletprovider.InstanceKey) error {
	if s.sweep {
		return walletprovider.ErrNotFound
	}
	return s.InstanceKeyStore.Update(ctx, k)
}

// TestInstanceKeySweptWhileMoved: a key swept while a request moves it
// to a later period's lists is refused as a key never recorded is, not
// as the provider's own failure.
func TestInstanceKeySweptWhileMoved(t *testing.T) {
	store := &sweptOnUpdate{}
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		withRetention(c, d)
		store.InstanceKeyStore = d.InstanceKeys
		d.InstanceKeys = store
	})
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	h.toNextPeriod()
	store.sweep = true
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); !errors.Is(err, walletprovider.ErrUnknownInstanceKey) {
		t.Fatalf("a Wallet Attestation for a key swept while moved = %v, want ErrUnknownInstanceKey", err)
	}
}

// TestSweepStatusListsRetainsUnretained: SweepStatusLists gives an
// instance key with no RetainUntil, as one recorded before retention
// has, the one its use would have set: from its list's period's start,
// or, on no period's list, from the current period's. A key with one
// is left alone, and a second sweep changes nothing.
func TestSweepStatusListsRetainsUnretained(t *testing.T) {
	h := newHarness(t, withRetention)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	recorded := h.periodStart()
	unretain := func(key *ecdsa.PrivateKey, status statuslist.StatusListRef) {
		t.Helper()
		ik := h.instanceKey(&key.PublicKey)
		ik.RetainUntil = time.Time{}
		if status.URI != "" {
			ik.Status = status
		}
		if err := h.deps.InstanceKeys.Update(ctx, ik); err != nil {
			t.Fatal(err)
		}
	}
	onPeriod, legacy, retained := h.newInstanceKey(in.ID, kindStrongBox), h.newInstanceKey(in.ID, kindStrongBox), h.newInstanceKey(in.ID, kindStrongBox)
	unretain(onPeriod, statuslist.StatusListRef{})
	unretain(legacy, statuslist.StatusListRef{Idx: 5, URI: statusBase})
	kept := h.instanceKey(&retained.PublicKey)
	h.toNextPeriod()
	h.toNextPeriod()

	h.sweep(0)
	for _, c := range []struct {
		what string
		key  *ecdsa.PrivateKey
		want time.Time
	}{
		{"a key on a period's list", onPeriod, time.Unix(recorded, 0).Add(3 * h.period())},
		{"a key on the single list", legacy, time.Unix(h.periodStart(), 0).Add(3 * h.period())},
		{"a key with a RetainUntil", retained, kept.RetainUntil},
	} {
		if got := h.instanceKey(&c.key.PublicKey).RetainUntil; !got.Equal(c.want) {
			t.Errorf("%s: RetainUntil = %v, want %v", c.what, got, c.want)
		}
	}
	if got := h.instanceKey(&retained.PublicKey); got.Revision != kept.Revision {
		t.Errorf("a key with a RetainUntil was updated: revision %d, was %d", got.Revision, kept.Revision)
	}
	before := h.instanceKey(&onPeriod.PublicKey).Revision
	h.sweep(0)
	if got := h.instanceKey(&onPeriod.PublicKey).Revision; got != before {
		t.Errorf("a second sweep updated a key again: revision %d, was %d", got, before)
	}
}

// TestSinglePreRotationListDeletable: the single status list of v0.67.0
// and before can be deleted whenever: a key still on it moves on its
// next use, and revoking its instance passes the list by.
func TestSinglePreRotationListDeletable(t *testing.T) {
	h := newHarness(t, withRetention)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	ik := h.instanceKey(&key.PublicKey)
	ik.Status = statuslist.StatusListRef{Idx: ik.Status.Idx, URI: statusBase}
	if err := h.deps.StatusIndices.Reserve(ctx, statusBase, ik.Status.Idx); err != nil {
		t.Fatal(err)
	}
	if err := h.deps.InstanceKeys.Update(ctx, ik); err != nil {
		t.Fatal(err)
	}
	if err := h.deps.StatusIndices.Delete(ctx, statusBase); err != nil {
		t.Fatal(err)
	}
	if _, err := h.walletAttestation(in.ID, &key.PublicKey, ""); err != nil {
		t.Fatalf("a Wallet Attestation for a key on the deleted single list: %v", err)
	}
	if ik := h.instanceKey(&key.PublicKey); ik.Status.URI != listURI(h.periodStart(), 0) {
		t.Fatalf("a key on the deleted single list moved to %+v", ik)
	}
	if err := h.p.Revoke(ctx, in.ID, "lost"); err != nil {
		t.Fatalf("Revoke with a key on the deleted single list: %v", err)
	}
	h.expectStatus(statuslist.StatusInvalid, key)
}
