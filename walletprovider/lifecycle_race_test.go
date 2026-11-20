package walletprovider_test

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// flakyInstances is an InstanceStore whose next Get, once armed, fails
// with failGet, or first calls cancel (its caller's context ending
// then), and each of whose Updates reports ErrConflict while conflicts
// is above zero, counting it down: another update winning the
// instance's compare-and-swap.
type flakyInstances struct {
	walletprovider.InstanceStore
	mu        sync.Mutex
	failGet   error
	cancel    context.CancelFunc
	conflicts int
}

func (s *flakyInstances) install(_ *walletprovider.Config, d *walletprovider.Dependencies) {
	s.InstanceStore = d.Instances
	d.Instances = s
}

func (s *flakyInstances) arm(failGet error, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failGet, s.cancel = failGet, cancel
}

func (s *flakyInstances) conflict(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conflicts = n
}

func (s *flakyInstances) Get(ctx context.Context, id string) (walletprovider.Instance, error) {
	s.mu.Lock()
	failGet, cancel := s.failGet, s.cancel
	s.failGet, s.cancel = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if failGet != nil {
		return walletprovider.Instance{}, failGet
	}
	return s.InstanceStore.Get(ctx, id)
}

func (s *flakyInstances) Update(ctx context.Context, in walletprovider.Instance) error {
	s.mu.Lock()
	conflict := s.conflicts > 0
	if conflict {
		s.conflicts--
	}
	s.mu.Unlock()
	if conflict {
		return walletprovider.ErrConflict
	}
	return s.InstanceStore.Update(ctx, in)
}

// TestFailedSettleRacingRevoke: a Resume overtaken by a Revoke that set
// its statuses, whose own VALID writes then land, and which then fails
// before it set the INVALID ones again — reading the instance back, its
// context ending there, or a write of its second pass — leaves the
// revocation pending, not recorded as finished over VALID statuses:
// RevokeWhere then finishes it.
func TestFailedSettleRacingRevoke(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  func(instances *flakyInstances, indices *failingIndices, cancel context.CancelFunc)
		want error
	}{{
		name: "reading the instance back fails",
		arm: func(instances *flakyInstances, _ *failingIndices, _ context.CancelFunc) {
			instances.arm(errStoreHiccup, nil)
		},
		want: errStoreHiccup,
	}, {
		name: "its context ends",
		arm: func(instances *flakyInstances, _ *failingIndices, cancel context.CancelFunc) {
			instances.arm(nil, cancel)
		},
		want: context.Canceled,
	}, {
		name: "a second pass write fails",
		arm: func(_ *flakyInstances, indices *failingIndices, _ context.CancelFunc) {
			// The key's one VALID write lands; the INVALID one setting it
			// again, for the state read back, fails.
			indices.failNext(1, 1)
		},
		want: errStoreHiccup,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			g := &gatedKeys{entered: make(chan struct{}), release: make(chan struct{})}
			indices, instances := &failingIndices{}, &flakyInstances{}
			h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
				g.InstanceKeyStore = d.InstanceKeys
				d.InstanceKeys = g
				indices.install(c, d)
				instances.install(c, d)
			})
			ctx := context.Background()
			in, _ := h.register(kindStrongBox)
			key := h.newInstanceKey(in.ID, kindStrongBox)
			if err := h.p.Suspend(ctx, in.ID, "lost"); err != nil {
				t.Fatal(err)
			}
			g.gate()
			resumeCtx, cancel := context.WithCancel(ctx)
			defer cancel()
			done := make(chan error)
			// Stores its state, then waits to list the instance's keys.
			go func() { done <- h.p.Resume(resumeCtx, in.ID) }()
			<-g.entered
			if err := h.p.Revoke(ctx, in.ID, "fraud"); err != nil {
				t.Fatal(err)
			}
			h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
			h.expectStatus(statuslist.StatusInvalid, key)
			tc.arm(instances, indices, cancel)
			close(g.release)
			if err := <-done; !errors.Is(err, tc.want) {
				t.Fatalf("Resume = %v, want %v", err, tc.want)
			}
			h.expectState(in.ID, walletprovider.StateRevoked, "fraud")
			h.expectKeyStatusesFor(in.ID, "")

			revoked := func(in walletprovider.Instance) bool { return in.State == walletprovider.StateRevoked }
			if n, err := h.p.RevokeWhere(ctx, revoked, ""); n != 1 || err != nil {
				t.Fatalf("RevokeWhere = %d, %v; want 1, nil", n, err)
			}
			h.expectState(in.ID, walletprovider.StateRevoked, "fraud")
			h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
			h.expectStatus(statuslist.StatusInvalid, key)
		})
	}
}

// TestRevokeWhereReadsBackRecentRevocations: a revocation recorded as
// finished whose statuses a racing transition overwrote, its process
// dying before it could say so, is found by RevokeWhere reading them
// back, while an attestation issued to the instance may still be live,
// and finished again; then a run writes nothing. Once none can be live,
// RevokeWhere passes the instance by unread.
func TestRevokeWhereReadsBackRecentRevocations(t *testing.T) {
	indices := &failingIndices{}
	h := newHarness(t, indices.install)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	if err := h.p.Revoke(ctx, in.ID, "fraud"); err != nil {
		t.Fatal(err)
	}
	h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
	ref := h.instanceKey(&key.PublicKey).Status
	// The dead Resume's write, landing after the revocation's.
	overwrite := func() {
		t.Helper()
		if err := indices.IndexStore.SetStatus(ctx, ref.URI, ref.Idx, statuslist.StatusValid); err != nil {
			t.Fatal(err)
		}
	}
	stored := func() statuslist.StatusType {
		t.Helper()
		status, err := indices.Status(ctx, ref.URI, ref.Idx)
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	revoked := func(in walletprovider.Instance) bool { return in.State == walletprovider.StateRevoked }

	overwrite()
	if n, err := h.p.RevokeWhere(ctx, revoked, ""); n != 1 || err != nil {
		t.Fatalf("RevokeWhere = %d, %v; want 1, nil", n, err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "fraud")
	h.expectStatus(statuslist.StatusInvalid, key)

	indices.writes()
	if n, err := h.p.RevokeWhere(ctx, revoked, ""); n != 0 || err != nil {
		t.Fatalf("RevokeWhere once finished = %d, %v; want 0, nil", n, err)
	}
	if w := indices.writes(); w != 0 {
		t.Fatalf("RevokeWhere once finished wrote %d statuses, want 0", w)
	}

	h.clock.advance(walletprovider.MaxAttestationTTL + 2*time.Hour)
	overwrite()
	if n, err := h.p.RevokeWhere(ctx, revoked, ""); n != 0 || err != nil {
		t.Fatalf("RevokeWhere with no attestation live = %d, %v; want 0, nil", n, err)
	}
	if got := stored(); got != statuslist.StatusValid {
		t.Fatalf("the status no live attestation names was set %v, want it left alone", got)
	}
}

// TestTransitionOutlastsConcurrentUpdates: an operator's Revoke keeps
// retrying while the instance's own requests win its record's
// compare-and-swap, more often than a request retries, and succeeds;
// a request still gives up; and the transition's context ends its
// retries.
func TestTransitionOutlastsConcurrentUpdates(t *testing.T) {
	instances := &flakyInstances{}
	h := newHarness(t, instances.install)
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	other, _ := h.register(kindStrongBox)
	otherKey := h.newInstanceKey(other.ID, kindStrongBox)

	instances.conflict(20)
	if err := h.p.Revoke(ctx, in.ID, "stolen"); err != nil {
		t.Fatalf("Revoke beaten 20 times = %v, want nil", err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "stolen")
	h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
	h.expectStatus(statuslist.StatusInvalid, key)

	instances.conflict(20)
	if _, err := h.walletAttestation(other.ID, &otherKey.PublicKey, ""); !errors.Is(err, walletprovider.ErrConflict) {
		t.Fatalf("a request beaten 20 times = %v, want ErrConflict", err)
	}

	instances.conflict(math.MaxInt)
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := h.p.Suspend(short, other.ID, "lost"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Suspend beaten until its context ends = %v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Suspend returned %v after its context ended", elapsed)
	}
	instances.conflict(0)
	h.expectState(other.ID, walletprovider.StateActive, "")
}
