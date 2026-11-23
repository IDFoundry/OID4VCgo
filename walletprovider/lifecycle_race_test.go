package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// flakyInstances is an InstanceStore whose next Get, once armed, fails
// with failGet, or first calls cancel (its caller's context ending
// then), or, once hung, closes hung and blocks until the test ends —
// its caller's process dying there — and each of whose Updates reports
// ErrConflict while conflicts is above zero, counting it down: another
// update winning the instance's compare-and-swap.
type flakyInstances struct {
	walletprovider.InstanceStore
	mu        sync.Mutex
	failGet   error
	cancel    context.CancelFunc
	hung      chan struct{}
	dead      chan struct{}
	conflicts int
}

var errProcessDied = errors.New("the process died")

// hangNext makes the next Get its caller's last: it returns, with
// errProcessDied, only once the test has ended. The returned channel
// is closed once that Get is reached.
func (s *flakyInstances) hangNext(t *testing.T) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hung, s.dead = make(chan struct{}), make(chan struct{})
	t.Cleanup(func() { close(s.dead) })
	return s.hung
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
	failGet, cancel, hung, dead := s.failGet, s.cancel, s.hung, s.dead
	s.failGet, s.cancel, s.hung = nil, nil, nil
	s.mu.Unlock()
	if hung != nil {
		close(hung)
		<-dead
		return walletprovider.Instance{}, errProcessDied
	}
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

// TestFinishTransitionsAfterResumeDied: a Resume overtaken by a Suspend
// or Revoke that set its statuses and recorded them as set, whose own
// VALID writes then land, and whose process dies before it reads the
// instance back, leaves the suspension or revocation recorded as
// finished over VALID statuses; the instance's requests don't finish
// it. FinishTransitions reads the statuses back and sets them again;
// then a run writes nothing.
func TestFinishTransitionsAfterResumeDied(t *testing.T) {
	for _, tc := range []struct {
		state  walletprovider.State
		status statuslist.StatusType
	}{
		{walletprovider.StateSuspended, statuslist.StatusSuspended},
		{walletprovider.StateRevoked, statuslist.StatusInvalid},
	} {
		t.Run(string(tc.state), func(t *testing.T) {
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
			keys := []*ecdsa.PrivateKey{h.newInstanceKey(in.ID, kindStrongBox), h.newInstanceKey(in.ID, kindTEE)}
			if err := h.p.Suspend(ctx, in.ID, "lost"); err != nil {
				t.Fatal(err)
			}
			g.gate()
			died := make(chan error)
			go func() { died <- h.p.Resume(ctx, in.ID) }()
			// After the hung Get returns, at the test's end.
			t.Cleanup(func() { <-died })
			<-g.entered
			// Stored after the Resume's state, set and recorded first.
			winner := h.p.Suspend
			if tc.state == walletprovider.StateRevoked {
				winner = h.p.Revoke
			}
			if err := winner(ctx, in.ID, "stolen"); err != nil {
				t.Fatal(err)
			}
			h.expectKeyStatusesFor(in.ID, tc.state)
			hung := instances.hangNext(t)
			close(g.release)
			<-hung // the Resume's VALID writes landed; it reads no further

			h.expectState(in.ID, tc.state, "stolen")
			h.expectKeyStatusesFor(in.ID, tc.state)
			h.expectStatus(statuslist.StatusValid, keys...)
			if _, err := h.walletAttestation(in.ID, &keys[0].PublicKey, ""); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
				t.Fatalf("the instance's next request = %v, want ErrInstanceNotActive", err)
			}
			h.expectStatus(statuslist.StatusValid, keys...)

			if n, err := h.p.FinishTransitions(ctx); n != 1 || err != nil {
				t.Fatalf("FinishTransitions = %d, %v; want 1, nil", n, err)
			}
			h.expectState(in.ID, tc.state, "stolen")
			h.expectKeyStatusesFor(in.ID, tc.state)
			h.expectStatus(tc.status, keys...)

			indices.writes()
			if n, err := h.p.FinishTransitions(ctx); n != 0 || err != nil {
				t.Fatalf("FinishTransitions once finished = %d, %v; want 0, nil", n, err)
			}
			if w := indices.writes(); w != 0 {
				t.Fatalf("FinishTransitions once finished wrote %d statuses, want 0", w)
			}
		})
	}
}

// TestFinishTransitionsYieldsToResume: an instance FinishTransitions
// read suspended, with a status not SUSPENDED, but resumed before it
// sets them, is left active with its statuses VALID; a pending
// suspension, whose status write failed, it finishes; an active
// instance it passes by.
func TestFinishTransitionsYieldsToResume(t *testing.T) {
	g := &gatedKeys{entered: make(chan struct{}), release: make(chan struct{})}
	indices := &failingIndices{}
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		g.InstanceKeyStore = d.InstanceKeys
		d.InstanceKeys = g
		indices.install(c, d)
	})
	ctx := context.Background()
	resumed, _ := h.register(kindStrongBox)
	resumedKey := h.newInstanceKey(resumed.ID, kindStrongBox)
	pending, _ := h.register(kindStrongBox)
	pendingKey := h.newInstanceKey(pending.ID, kindStrongBox)
	active, _ := h.register(kindStrongBox)
	activeKey := h.newInstanceKey(active.ID, kindStrongBox)

	if err := h.p.Suspend(ctx, resumed.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	ref := h.instanceKey(&resumedKey.PublicKey).Status
	if err := indices.IndexStore.SetStatus(ctx, ref.URI, ref.Idx, statuslist.StatusValid); err != nil {
		t.Fatal(err)
	}
	indices.failNext(0, 1)
	if err := h.p.Suspend(ctx, pending.ID, "lost"); !errors.Is(err, errStoreHiccup) {
		t.Fatalf("Suspend = %v, want the store's failure", err)
	}

	// Gates the first listing of an instance's keys: reading the
	// resumed instance's statuses back, or setting the pending one's
	// (which reads none back: its KeyStatusesFor isn't its State).
	g.gate()
	done := make(chan error)
	go func() {
		n, err := h.p.FinishTransitions(ctx)
		if err == nil && n != 1 {
			err = fmt.Errorf("finished %d instances, want 1", n)
		}
		done <- err
	}()
	select {
	case <-g.entered:
	case err := <-done:
		t.Fatalf("FinishTransitions = %v, without listing an instance's keys", err)
	}
	if err := h.p.Resume(ctx, resumed.ID); err != nil {
		t.Fatal(err)
	}
	close(g.release)
	if err := <-done; err != nil {
		t.Fatalf("FinishTransitions: %v", err)
	}
	h.expectState(resumed.ID, walletprovider.StateActive, "")
	h.expectKeyStatusesFor(resumed.ID, walletprovider.StateActive)
	h.expectStatus(statuslist.StatusValid, resumedKey, activeKey)
	h.expectKeyStatusesFor(pending.ID, walletprovider.StateSuspended)
	h.expectStatus(statuslist.StatusSuspended, pendingKey)
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
