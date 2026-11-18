package walletprovider_test

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// failingIndices is an IndexStore whose SetStatus, once armed by
// failNext, lets ok calls through and fails the fail after them,
// counting every call.
type failingIndices struct {
	statuslist.IndexStore
	mu       sync.Mutex
	ok, fail int
	calls    int
}

var errStoreHiccup = errors.New("transient store failure")

func (s *failingIndices) failNext(ok, fail int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ok, s.fail = ok, fail
}

// writes returns how many SetStatus calls were made since it was last
// called.
func (s *failingIndices) writes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.calls
	s.calls = 0
	return n
}

func (s *failingIndices) SetStatus(ctx context.Context, uri string, idx uint64, status statuslist.StatusType) error {
	s.mu.Lock()
	s.calls++
	fail := false
	switch {
	case s.ok > 0:
		s.ok--
	case s.fail > 0:
		s.fail--
		fail = true
	}
	s.mu.Unlock()
	if fail {
		return errStoreHiccup
	}
	return s.IndexStore.SetStatus(ctx, uri, idx, status)
}

// install makes s, over the harness's IndexStore, its StatusIndices.
func (s *failingIndices) install(_ *walletprovider.Config, d *walletprovider.Dependencies) {
	s.IndexStore = d.StatusIndices
	d.StatusIndices = s
}

func (h *harness) expectKeyStatusesFor(id string, want walletprovider.State) {
	h.t.Helper()
	if got := h.stored(id).KeyStatusesFor; got != want {
		h.t.Fatalf("instance %s's KeyStatusesFor = %q, want %q", id, got, want)
	}
}

// TestRevokeWhereFinishesPendingRevocation: a revocation whose status
// writes fail part-way leaves the instance revoked with its statuses
// pending. RevokeWhere goes on to the next instance, names the one that
// failed, and its documented re-run finishes it; once every status is
// set, another run writes nothing.
func TestRevokeWhereFinishesPendingRevocation(t *testing.T) {
	indices := &failingIndices{}
	h := newHarness(t, indices.install)
	ctx := context.Background()
	a, _ := h.register(kindStrongBox)
	b, _ := h.register(kindStrongBox)
	first, second := a, b
	if b.ID < a.ID {
		first, second = b, a
	}
	firstKeys := []*ecdsa.PrivateKey{h.newInstanceKey(first.ID, kindStrongBox), h.newInstanceKey(first.ID, kindTEE)}
	secondKey := h.newInstanceKey(second.ID, kindStrongBox)
	h.expectKeyStatusesFor(first.ID, walletprovider.StateActive)
	all := func(walletprovider.Instance) bool { return true }

	// The second of the first instance's writes fails.
	indices.failNext(1, 1)
	n, err := h.p.RevokeWhere(ctx, all, "chain revoked")
	var rwErr *walletprovider.RevokeWhereError
	if !errors.As(err, &rwErr) || !errors.Is(err, errStoreHiccup) {
		t.Fatalf("RevokeWhere = %d, %v; want a *RevokeWhereError wrapping the store's", n, err)
	}
	if n != 1 || len(rwErr.Failed) != 1 || rwErr.Failed[0].ID != first.ID || rwErr.Err != nil {
		t.Fatalf("RevokeWhere = %d, %+v; want 1 revoked, %s failed", n, rwErr, first.ID)
	}
	h.expectState(first.ID, walletprovider.StateRevoked, "chain revoked")
	h.expectKeyStatusesFor(first.ID, walletprovider.StateActive)
	h.expectState(second.ID, walletprovider.StateRevoked, "chain revoked")
	h.expectKeyStatusesFor(second.ID, walletprovider.StateRevoked)
	h.expectStatus(statuslist.StatusInvalid, secondKey)

	// The documented re-run finishes it, keeping its reason.
	if n, err := h.p.RevokeWhere(ctx, all, "again"); n != 1 || err != nil {
		t.Fatalf("RevokeWhere re-run = %d, %v; want 1, nil", n, err)
	}
	h.expectState(first.ID, walletprovider.StateRevoked, "chain revoked")
	h.expectKeyStatusesFor(first.ID, walletprovider.StateRevoked)
	h.expectStatus(statuslist.StatusInvalid, firstKeys...)

	// Then nothing is pending: a run writes nothing.
	indices.writes()
	if n, err := h.p.RevokeWhere(ctx, all, "again"); n != 0 || err != nil {
		t.Fatalf("RevokeWhere once finished = %d, %v; want 0, nil", n, err)
	}
	if w := indices.writes(); w != 0 {
		t.Fatalf("RevokeWhere once finished wrote %d statuses, want 0", w)
	}
}

// TestRevokeWhereStopsWhenContextEnds: RevokeWhere goes on past a
// failed instance, but not past its context's end.
func TestRevokeWhereStopsWhenContextEnds(t *testing.T) {
	h := newHarness(t, nil)
	for range 3 {
		h.register(kindStrongBox)
	}
	ctx, cancel := context.WithCancel(context.Background())
	matched := 0
	n, err := h.p.RevokeWhere(ctx, func(walletprovider.Instance) bool {
		matched++
		cancel()
		return true
	}, "x")
	var rwErr *walletprovider.RevokeWhereError
	if !errors.As(err, &rwErr) || !errors.Is(rwErr.Err, context.Canceled) {
		t.Fatalf("RevokeWhere whose context ends = %d, %v; want a *RevokeWhereError, Err context.Canceled", n, err)
	}
	if n != 0 || matched != 1 || len(rwErr.Failed) != 1 {
		t.Fatalf("RevokeWhere = %d, %d matched, %d failed; want it to stop at the first", n, matched, len(rwErr.Failed))
	}
}

// TestPendingTransitionFinishedByNextRequest: an automatic revocation
// or suspension whose status write fails is reported to
// OnRecheckRefused, and the instance's next request sets the statuses
// before it's refused for the stored state, through VerifyRequest and
// through WalletAttestation. Once they're set, a request writes none.
func TestPendingTransitionFinishedByNextRequest(t *testing.T) {
	for _, tc := range []struct {
		name    string
		verdict error
		state   walletprovider.State
		status  statuslist.StatusType
	}{
		{"revoked", walletprovider.ErrEvidenceRevoked, walletprovider.StateRevoked, statuslist.StatusInvalid},
		{"suspended", walletprovider.ErrEvidenceSuspended, walletprovider.StateSuspended, statuslist.StatusSuspended},
	} {
		for _, via := range []string{"VerifyRequest", "WalletAttestation"} {
			t.Run(tc.name+"/"+via, func(t *testing.T) {
				v, log, indices := &recheckingVerifier{}, &refusalLog{}, &failingIndices{}
				h := recheckHarness(t, v, log, indices.install)
				in, regKey := h.register(kindStrongBox)
				keys := []*ecdsa.PrivateKey{h.newInstanceKey(in.ID, kindStrongBox), h.newInstanceKey(in.ID, kindTEE)}

				verdict := fmt.Errorf("%w: %w: certificate 1", walletprovider.ErrEvidenceRejected, tc.verdict)
				v.refuse(verdict)
				indices.failNext(0, 1)
				if _, err := h.walletAttestation(in.ID, &keys[0].PublicKey, ""); !errors.Is(err, errStoreHiccup) {
					t.Fatalf("the request whose transition fails = %v, want the store's failure", err)
				}
				stored := h.stored(in.ID)
				log.expect(t, 1, stored, tc.verdict)
				if stored.State != tc.state || stored.KeyStatusesFor == tc.state {
					t.Fatalf("instance is %s, its key statuses for %q; want %s, pending", stored.State, stored.KeyStatusesFor, tc.state)
				}
				if log.calls[0].in.KeyStatusesFor == tc.state {
					t.Fatal("OnRecheckRefused was told the statuses are set")
				}

				request := func() error {
					if via == "VerifyRequest" {
						_, err := h.p.VerifyRequest(context.Background(), h.signRequest(regKey, in.ID, h.challenge(walletprovider.PurposeRequest)))
						return err
					}
					_, err := h.walletAttestation(in.ID, &keys[0].PublicKey, "")
					return err
				}
				indices.writes()
				if err := request(); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
					t.Fatalf("the next request = %v, want ErrInstanceNotActive", err)
				}
				// Two keys, each with one index on a served list.
				if w := indices.writes(); w != len(keys) {
					t.Fatalf("the next request wrote %d statuses, want %d", w, len(keys))
				}
				h.expectStatus(tc.status, keys...)
				h.expectKeyStatusesFor(in.ID, tc.state)

				if err := request(); !errors.Is(err, walletprovider.ErrInstanceNotActive) {
					t.Fatalf("a later request = %v, want ErrInstanceNotActive", err)
				}
				if w := indices.writes(); w != 0 {
					t.Fatalf("a request once the statuses are set wrote %d, want 0", w)
				}
				log.expect(t, 1, h.stored(in.ID), tc.verdict)
			})
		}
	}
}

// TestFailedTransitionRacingRevoke: a Resume overtaken by a Revoke that
// set its statuses, whose own writes then fail, leaves the revocation
// pending: its writes may have overwritten the INVALID ones.
func TestFailedTransitionRacingRevoke(t *testing.T) {
	g := &gatedKeys{entered: make(chan struct{}), release: make(chan struct{})}
	indices := &failingIndices{}
	h := newHarness(t, func(c *walletprovider.Config, d *walletprovider.Dependencies) {
		g.InstanceKeyStore = d.InstanceKeys
		d.InstanceKeys = g
		indices.install(c, d)
	})
	ctx := context.Background()
	in, _ := h.register(kindStrongBox)
	key := h.newInstanceKey(in.ID, kindStrongBox)
	if err := h.p.Suspend(ctx, in.ID, "lost"); err != nil {
		t.Fatal(err)
	}
	g.gate()
	done := make(chan error)
	go func() { done <- h.p.Resume(ctx, in.ID) }()
	<-g.entered
	if err := h.p.Revoke(ctx, in.ID, "fraud"); err != nil {
		t.Fatal(err)
	}
	h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
	indices.failNext(0, 1)
	close(g.release)
	if err := <-done; !errors.Is(err, errStoreHiccup) {
		t.Fatalf("Resume = %v, want the store's failure", err)
	}
	h.expectKeyStatusesFor(in.ID, "")
	revoked := func(in walletprovider.Instance) bool { return in.State == walletprovider.StateRevoked }
	if n, err := h.p.RevokeWhere(ctx, revoked, ""); n != 1 || err != nil {
		t.Fatalf("RevokeWhere = %d, %v; want 1, nil", n, err)
	}
	h.expectState(in.ID, walletprovider.StateRevoked, "fraud")
	h.expectKeyStatusesFor(in.ID, walletprovider.StateRevoked)
	h.expectStatus(statuslist.StatusInvalid, key)
}

// TestRevokeWhereErrorNamesInstances: the error lists each failed
// instance's ID.
func TestRevokeWhereErrorNamesInstances(t *testing.T) {
	err := &walletprovider.RevokeWhereError{Failed: []walletprovider.InstanceError{{ID: "a", Err: errStoreHiccup}, {ID: "b", Err: errStoreHiccup}}}
	msg := err.Error()
	for _, want := range []string{"(a, b)", errStoreHiccup.Error()} {
		if !strings.Contains(msg, want) {
			t.Fatalf("%q doesn't name %q", msg, want)
		}
	}
}
