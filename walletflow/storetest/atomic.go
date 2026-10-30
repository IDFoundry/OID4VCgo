package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// errContract is what a contract check's update function fails with, to
// abort an update.
var errContract = errors.New("storetest: aborted by the contract")

// updatable is how the atomicity checks change one kind of record.
type updatable[T any] struct {
	// add records n in r, beside what earlier adds recorded; has reports
	// whether r records n.
	add func(r *T, n int)
	has func(r T, n int) bool
	// claimable is a record with slots things to give out, each once;
	// claim gives out the next one to claimant n, or fails when none is
	// left; owner is the claimant slot went to.
	claimable func(id string) T
	slots     int
	claim     func(r *T, n int) (slot int, err error)
	owner     func(r T, slot int) string
}

// runUpdateContract runs the Update checks on handles open returns: one
// storage each time open is called by the factory, each call to the
// opener it returns a handle on that storage.
func runUpdateContract[T any](t *testing.T, kind recordKind[T], u updatable[T], factory func() func() recordStore[T]) {
	t.Helper()
	c := updateContract[T]{recordContract: recordContract[T]{kind: kind}, u: u}
	cases := []struct {
		name string
		run  func(*testing.T, func() recordStore[T])
	}{
		{"UpdateStoresWhatFnLeaves", c.updateStores},
		{"UpdateUnknownIsNotFound", c.updateUnknown},
		{"UpdateAbortedStoresNothing", c.updateAborted},
		{"UpdateCancelledContext", c.updateCancelled},
		{"ConcurrentUpdatesLoseNothing", c.concurrentUpdates},
		{"RacingClaimsGiveEachOutOnce", c.racingClaims},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, factory()) })
	}
}

type updateContract[T any] struct {
	recordContract[T]
	u updatable[T]
}

func (c updateContract[T]) updateStores(t *testing.T, open func() recordStore[T]) {
	s := open()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	keep := c.kind.full("rec-2", 2)
	c.mustPut(t, s, keep)
	want := c.kind.full("rec-1", 3)
	if err := s.update(context.Background(), "rec-1", func(r *T) error {
		*r = want
		return nil
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	expectEqual(t, "after Update", c.mustFind(t, open(), "rec-1"), want)
	expectEqual(t, "the record not updated", c.mustFind(t, open(), "rec-2"), keep)
	minimal := c.kind.minimal("rec-1")
	if err := s.update(context.Background(), "rec-1", func(r *T) error {
		*r = minimal
		return nil
	}); err != nil {
		t.Fatalf("Update to a minimal record: %v", err)
	}
	expectEqual(t, "after an Update clearing fields", c.mustFind(t, open(), "rec-1"), minimal)
}

func (c updateContract[T]) updateUnknown(t *testing.T, open func() recordStore[T]) {
	s := open()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	called := false
	err := s.update(context.Background(), "unknown", func(r *T) error {
		called = true
		return nil
	})
	if !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Update(unknown) = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
	if called {
		t.Error("Update(unknown) called fn")
	}
	c.mustBeGone(t, s, "unknown")
}

// updateAborted: fn's error is returned and nothing is stored — not
// even what fn changed in place, deep in the record, before failing.
func (c updateContract[T]) updateAborted(t *testing.T, open func() recordStore[T]) {
	s := open()
	want := c.kind.full("rec-1", 1)
	c.mustPut(t, s, want)
	err := s.update(context.Background(), "rec-1", func(r *T) error {
		c.u.add(r, 7)
		return errContract
	})
	if !errors.Is(err, errContract) {
		t.Errorf("Update with fn failing = %v, want fn's error", err)
	}
	expectEqual(t, "after an aborted Update", c.mustFind(t, open(), "rec-1"), want)
}

func (c updateContract[T]) updateCancelled(t *testing.T, open func() recordStore[T]) {
	s := open()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	want := c.kind.full("rec-1", 2)
	if err := s.update(ctx, "rec-1", func(r *T) error {
		*r = want
		return nil
	}); err != nil {
		expectCanceled(t, "Update", err)
		want = c.kind.full("rec-1", 1)
	}
	expectEqual(t, "after Update with a cancelled context", c.mustFind(t, open(), "rec-1"), want)
}

// concurrentUpdates: of concurrent Updates of one record, from separate
// handles where the factory gives them, none is lost — each one's
// change is in the outcome.
func (c updateContract[T]) concurrentUpdates(t *testing.T, open func() recordStore[T]) {
	c.mustPut(t, open(), c.kind.minimal("rec-1"))
	var wg sync.WaitGroup
	errs := make(chan error, contractConcurrency)
	for n := range contractConcurrency {
		s := open()
		wg.Go(func() {
			errs <- s.update(context.Background(), "rec-1", func(r *T) error {
				c.u.add(r, n)
				return nil
			})
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Update: %v", err)
		}
	}
	got := c.mustFind(t, open(), "rec-1")
	for n := range contractConcurrency {
		if !c.u.has(got, n) {
			t.Errorf("concurrent Update %d was lost", n)
		}
	}
}

// racingClaims: Updates racing — from separate handles where the factory
// gives them — to claim what a record has to give out, each thing once
// (a credential's unused copy, a refresh grant's redemption), give each
// to exactly one claimant: never one thing to two.
func (c updateContract[T]) racingClaims(t *testing.T, open func() recordStore[T]) {
	c.mustPut(t, open(), c.u.claimable("rec-1"))
	type result struct {
		n, slot int
		err     error
	}
	results := make(chan result, contractConcurrency)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for n := range contractConcurrency {
		s := open()
		wg.Go(func() {
			<-start
			var slot int
			err := s.update(context.Background(), "rec-1", func(r *T) error {
				var err error
				slot, err = c.u.claim(r, n)
				return err
			})
			results <- result{n, slot, err}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	won := map[int]int{} // slot → claimant
	for r := range results {
		switch {
		case errors.Is(r.err, errContract):
		case r.err != nil:
			t.Errorf("racing Update: %v", r.err)
		default:
			if prev, ok := won[r.slot]; ok {
				t.Errorf("claimants %d and %d were both given %d", prev, r.n, r.slot)
			}
			won[r.slot] = r.n
		}
	}
	if len(won) != c.u.slots {
		t.Errorf("%d given out, want all %d", len(won), c.u.slots)
	}
	got := c.mustFind(t, open(), "rec-1")
	for slot, n := range won {
		if owner := c.u.owner(got, slot); owner != strconv.Itoa(n) {
			t.Errorf("%d went to claimant %d, but the store records %q", slot, n, owner)
		}
	}
}

// runConsumeContract runs the ConsumeAuthorization checks: consume
// returns a record and deletes it, atomically.
func runConsumeContract[T any](t *testing.T, kind recordKind[T], factory func() func() recordStore[T]) {
	t.Helper()
	c := consumeContract[T]{recordContract: recordContract[T]{kind: kind}}
	cases := []struct {
		name string
		run  func(*testing.T, func() recordStore[T])
	}{
		{"ConsumeReturnsAndDeletes", c.consumeDeletes},
		{"ConsumeUnknownIsNotFound", c.consumeUnknown},
		{"ConsumeCancelledContext", c.consumeCancelled},
		{"RacingConsumesHaveOneWinner", c.racingConsumes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, factory()) })
	}
}

type consumeContract[T any] struct{ recordContract[T] }

func (c consumeContract[T]) consumeDeletes(t *testing.T, open func() recordStore[T]) {
	s := open()
	want := c.kind.full("rec-1", 1)
	c.mustPut(t, s, want)
	keep := c.kind.full("rec-2", 2)
	c.mustPut(t, s, keep)
	got, err := s.consume(context.Background(), "rec-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	expectEqual(t, "Consume", got, want)
	c.mustBeGone(t, open(), "rec-1")
	expectEqual(t, "the record not consumed", c.mustFind(t, open(), "rec-2"), keep)
	if _, err := s.consume(context.Background(), "rec-1"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Consume again = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
}

func (c consumeContract[T]) consumeUnknown(t *testing.T, open func() recordStore[T]) {
	s := open()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	if _, err := s.consume(context.Background(), "unknown"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Consume(unknown) = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
	c.mustFind(t, s, "rec-1")
}

func (c consumeContract[T]) consumeCancelled(t *testing.T, open func() recordStore[T]) {
	s := open()
	want := c.kind.full("rec-1", 1)
	c.mustPut(t, s, want)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := s.consume(ctx, "rec-1")
	if err != nil {
		expectCanceled(t, "Consume", err)
		c.mustFind(t, open(), "rec-1")
		return
	}
	expectEqual(t, "Consume with a cancelled context", got, want)
	c.mustBeGone(t, open(), "rec-1")
}

// racingConsumes: of concurrent consumes of one record, from separate
// handles where the factory gives them, exactly one gets it; the others
// find it gone.
func (c consumeContract[T]) racingConsumes(t *testing.T, open func() recordStore[T]) {
	want := c.kind.full("rec-1", 1)
	c.mustPut(t, open(), want)
	var mu sync.Mutex
	var winners []T
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range contractConcurrency {
		consume := open().consume
		wg.Go(func() {
			<-start
			got, err := consume(context.Background(), "rec-1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners = append(winners, got)
			case !errors.Is(err, walletflow.ErrNotFound):
				t.Errorf("racing Consume = %v; want the record, or an error wrapping walletflow.ErrNotFound", err)
			}
		})
	}
	close(start)
	wg.Wait()
	if len(winners) != 1 {
		t.Fatalf("%d racing Consumes got the record, want exactly 1", len(winners))
	}
	expectEqual(t, "the winning Consume", winners[0], want)
	c.mustBeGone(t, open(), "rec-1")
}

// numbered is n as add records it.
func numbered(n int) string { return fmt.Sprintf("n%d", n) }

// containsNumbered reports whether list records n (numbered).
func containsNumbered(list []string, n int) bool { return slices.Contains(list, numbered(n)) }
