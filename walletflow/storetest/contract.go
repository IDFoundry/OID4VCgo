// Package storetest holds reusable contract tests for walletflow's
// store interfaces — CredentialStore, AuthorizationStore, GrantStore,
// DeferredStore and KeyStore — for a caller testing its own
// implementation, the way issuertest and verifiertest do for the
// issuer's and verifier's stores. It imports "testing": import it only
// from _test.go files.
//
// Each TestXContract takes a factory that must return a fresh, empty
// store each call: its subtests share nothing. A store passes when it
// keeps every field of every record (a fully populated fixture, which
// a reflection check keeps fully populated as the record types grow),
// replaces a record whole on Put, reports a missing one with
// walletflow.ErrNotFound where the interface says so, lists every
// record it holds, deletes idempotently, treats IDs as case-sensitive
// opaque strings, is safe for concurrent use (run with -race), and,
// given a cancelled context, either completes the call or fails it
// with the context's error and no change.
//
// It checks the atomic operations walletflow's read-modify-write rests
// on, which make one store safe to share between Wallets in several
// processes — an app and its extension, a server's replicas: of
// concurrent ConsumeAuthorization calls for one authorization exactly
// one gets it; concurrent Update (UpdateGrant) calls of one record lose
// none of their changes, and racing ones claiming what a record gives
// out once — a credential's unused copy, a grant's one redemption —
// never give one thing to two; an aborted update stores nothing. The
// TestSharedXContract functions run those checks with every goroutine on
// its own handle on one storage, as separate processes have; run them
// too where a store can open more than one (a database, a directory).
//
// What it doesn't check: that a store is durable (Durable, or
// keys.KeyCustodyAssurance), only that it says so consistently; and
// that its handles in separate processes exclude each other, which a
// test in one process can only approach with separate handles.
//
// Times are compared with time.Time.Equal, to millisecond precision:
// walletflow writes UTC times, and a store may return them in another
// location. Durations are whole seconds, as the issuers' intervals are.
// Claims hold JSON values (string, float64, bool, nil, []any,
// map[string]any), as a credential's are once checked.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// contractConcurrency is how many goroutines the concurrent checks fan
// out to.
const contractConcurrency = 20

// contractListSize is how many records the listing check stores: more
// than a store paging its results by a round number would return at
// once.
const contractListSize = 150

// contractBase is the time the fixtures' times are offset from, at
// millisecond precision.
var contractBase = time.Date(2026, time.October, 30, 12, 34, 56, 789_000_000, time.UTC)

// recordStore is one of walletflow's record stores, as the contract
// drives it.
type recordStore[T any] struct {
	put func(context.Context, T) error
	// get is nil for a store with no lookup by ID (DeferredStore).
	get  func(context.Context, string) (T, error)
	list func(context.Context) ([]T, error)
	del  func(context.Context, string) error
	// durable is nil for a store that doesn't declare it.
	durable func() bool
	// update is nil for a store with no atomic update.
	update func(context.Context, string, func(*T) error) error
	// consume is nil for a store with no atomic consume.
	consume func(context.Context, string) (T, error)
}

// sameHandle opens s each time: for a factory giving one handle on each
// storage.
func sameHandle[T any](s recordStore[T]) func() recordStore[T] {
	return func() recordStore[T] { return s }
}

// recordKind is a record type, as the contract builds and identifies
// its records.
type recordKind[T any] struct {
	// id is the key a record is stored under.
	id func(T) string
	// full is a record with every field set, its values derived from v,
	// so records with different v differ in every field.
	full func(id string, v int) T
	// minimal is a record with only the fields walletflow always sets.
	minimal func(id string) T
}

// runRecordContract runs the record store contract on stores factory
// returns.
func runRecordContract[T any](t *testing.T, kind recordKind[T], factory func() recordStore[T]) {
	t.Helper()
	c := recordContract[T]{kind: kind}
	cases := []struct {
		name string
		run  func(*testing.T, recordStore[T])
	}{
		{"FullRoundTrip", c.fullRoundTrip},
		{"MinimalRoundTrip", c.minimalRoundTrip},
		{"PutReplacesWholeRecord", c.putReplaces},
		{"UnknownIsNotFound", c.unknown},
		{"DeleteRemovesOnlyThatRecord", c.deleteRemoves},
		{"DeleteUnknownIsNotAnError", c.deleteUnknown},
		{"ListReturnsEveryRecord", c.listEvery},
		{"IDsAreCaseSensitive", c.caseSensitive},
		{"ConcurrentPutsOfDistinctRecords", c.concurrentDistinct},
		{"ConcurrentPutsOfOneRecordAreWhole", c.concurrentOne},
		{"ConcurrentMixedUse", c.concurrentMixed},
		{"CancelledContext", c.cancelled},
		{"DurableIsConsistent", c.durableConsistent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, factory()) })
	}
}

type recordContract[T any] struct{ kind recordKind[T] }

// lookup returns the record id names, and whether it's there: by get,
// or by listing for a store without one.
func (c recordContract[T]) lookup(ctx context.Context, s recordStore[T], id string) (T, bool, error) {
	var zero T
	if s.get != nil {
		r, err := s.get(ctx, id)
		if errors.Is(err, walletflow.ErrNotFound) {
			return zero, false, nil
		}
		if err != nil {
			return zero, false, err
		}
		if got := c.kind.id(r); got != id {
			return zero, false, fmt.Errorf("get(%q) returned the record for %q", id, got)
		}
		return r, true, nil
	}
	all, err := s.list(ctx)
	if err != nil {
		return zero, false, err
	}
	for _, r := range all {
		if c.kind.id(r) == id {
			return r, true, nil
		}
	}
	return zero, false, nil
}

func (c recordContract[T]) mustPut(t *testing.T, s recordStore[T], r T) {
	t.Helper()
	if err := s.put(context.Background(), r); err != nil {
		t.Fatalf("Put(%q): %v", c.kind.id(r), err)
	}
}

// mustFind fails t unless the record id names is there, and returns it.
func (c recordContract[T]) mustFind(t *testing.T, s recordStore[T], id string) T {
	t.Helper()
	r, ok, err := c.lookup(context.Background(), s, id)
	if err != nil {
		t.Fatalf("look up %q: %v", id, err)
	}
	if !ok {
		t.Fatalf("look up %q: not found, want the record stored", id)
	}
	return r
}

// mustBeGone fails t if the record id names is there.
func (c recordContract[T]) mustBeGone(t *testing.T, s recordStore[T], id string) {
	t.Helper()
	if _, ok, err := c.lookup(context.Background(), s, id); err != nil || ok {
		t.Errorf("look up %q = found %v, %v; want not found", id, ok, err)
	}
}

// expectEqual fails t where got differs from want.
func expectEqual[T any](t *testing.T, what string, got, want T) {
	t.Helper()
	for _, d := range diff(got, want) {
		t.Errorf("%s: %s", what, d)
	}
}

func (c recordContract[T]) fullRoundTrip(t *testing.T, s recordStore[T]) {
	want := c.kind.full("rec-1", 1)
	if missing := unset(want); len(missing) > 0 {
		t.Fatalf("the fixture leaves %s unset: give every field a value", strings.Join(missing, ", "))
	}
	c.mustPut(t, s, want)
	expectEqual(t, "after Put", c.mustFind(t, s, "rec-1"), want)
	all, err := s.list(context.Background())
	if err != nil || len(all) != 1 {
		t.Fatalf("List = %d records, %v; want the 1 stored", len(all), err)
	}
	expectEqual(t, "List", all[0], want)
}

func (c recordContract[T]) minimalRoundTrip(t *testing.T, s recordStore[T]) {
	want := c.kind.minimal("rec-1")
	c.mustPut(t, s, want)
	expectEqual(t, "after Put of a minimal record", c.mustFind(t, s, "rec-1"), want)
}

// putReplaces: a Put replaces the whole record, clearing the fields the
// new one leaves empty — not merging.
func (c recordContract[T]) putReplaces(t *testing.T, s recordStore[T]) {
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	minimal := c.kind.minimal("rec-1")
	c.mustPut(t, s, minimal)
	expectEqual(t, "after replacing a full record with a minimal one", c.mustFind(t, s, "rec-1"), minimal)
	second := c.kind.full("rec-1", 2)
	c.mustPut(t, s, second)
	expectEqual(t, "after replacing it again", c.mustFind(t, s, "rec-1"), second)
	if all, err := s.list(context.Background()); err != nil || len(all) != 1 {
		t.Errorf("List after replacing = %d records, %v; want 1", len(all), err)
	}
}

func (c recordContract[T]) unknown(t *testing.T, s recordStore[T]) {
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	if s.get == nil {
		c.mustBeGone(t, s, "unknown")
		return
	}
	if _, err := s.get(context.Background(), "unknown"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Get(unknown) = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
}

func (c recordContract[T]) deleteRemoves(t *testing.T, s recordStore[T]) {
	ctx := context.Background()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	keep := c.kind.full("rec-2", 2)
	c.mustPut(t, s, keep)
	if err := s.del(ctx, "rec-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	c.mustBeGone(t, s, "rec-1")
	if s.get != nil {
		if _, err := s.get(ctx, "rec-1"); !errors.Is(err, walletflow.ErrNotFound) {
			t.Errorf("Get of a deleted record = %v, want an error wrapping walletflow.ErrNotFound", err)
		}
	}
	expectEqual(t, "the record not deleted", c.mustFind(t, s, "rec-2"), keep)
	if err := s.del(ctx, "rec-1"); err != nil {
		t.Errorf("Delete again = %v, want nil", err)
	}
}

func (c recordContract[T]) deleteUnknown(t *testing.T, s recordStore[T]) {
	if err := s.del(context.Background(), "unknown"); err != nil {
		t.Errorf("Delete(unknown) on an empty store = %v, want nil", err)
	}
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	if err := s.del(context.Background(), "unknown"); err != nil {
		t.Errorf("Delete(unknown) = %v, want nil", err)
	}
	c.mustFind(t, s, "rec-1")
}

// listEvery: List returns every record, once each. walletflow sweeps
// keys and revokes refresh grants that no listed record names, so a
// record a listing leaves out loses its keys.
func (c recordContract[T]) listEvery(t *testing.T, s recordStore[T]) {
	ctx := context.Background()
	if all, err := s.list(ctx); err != nil || len(all) != 0 {
		t.Fatalf("List of an empty store = %d records, %v; want none", len(all), err)
	}
	want := map[string]T{}
	for i := range contractListSize {
		r := c.kind.full(fmt.Sprintf("rec-%03d", i), i)
		want[c.kind.id(r)] = r
		c.mustPut(t, s, r)
	}
	all, err := s.list(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	c.expectExactly(t, all, want)
}

// expectExactly fails t unless all holds want's records, once each.
func (c recordContract[T]) expectExactly(t *testing.T, all []T, want map[string]T) {
	t.Helper()
	seen := map[string]bool{}
	for _, r := range all {
		id := c.kind.id(r)
		w, ok := want[id]
		switch {
		case !ok:
			t.Errorf("List returned %q, which wasn't stored", id)
		case seen[id]:
			t.Errorf("List returned %q twice", id)
		default:
			expectEqual(t, "List's "+id, r, w)
		}
		seen[id] = true
	}
	for id := range want {
		if !seen[id] {
			t.Errorf("List left out %q", id)
		}
	}
}

// caseSensitive: IDs are case-sensitive opaque strings — walletflow's
// are random base64url — so two differing only in case are two records.
// A database column with a case-insensitive collation fails this.
func (c recordContract[T]) caseSensitive(t *testing.T, s recordStore[T]) {
	ids := []string{"Ab-_9xYz", "aB-_9XyZ", "ab-_9xyz", strings.Repeat("Zz09-_", 21)}
	want := map[string]T{}
	for i, id := range ids {
		r := c.kind.full(id, i)
		want[id] = r
		c.mustPut(t, s, r)
	}
	for id, r := range want {
		expectEqual(t, "record "+id, c.mustFind(t, s, id), r)
	}
	all, err := s.list(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	c.expectExactly(t, all, want)
}

func (c recordContract[T]) concurrentDistinct(t *testing.T, s recordStore[T]) {
	want := map[string]T{}
	for i := range contractConcurrency {
		r := c.kind.full(fmt.Sprintf("rec-%02d", i), i)
		want[c.kind.id(r)] = r
	}
	errs := make(chan error, len(want))
	var wg sync.WaitGroup
	for _, r := range want {
		wg.Go(func() { errs <- s.put(context.Background(), r) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent Put: %v", err)
		}
	}
	all, err := s.list(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	c.expectExactly(t, all, want)
}

// concurrentOne: of concurrent Puts of one record, and reads alongside
// them, every read and the outcome is one Put's record whole, never a
// mix of two.
func (c recordContract[T]) concurrentOne(t *testing.T, s recordStore[T]) {
	const id = "rec-1"
	c.mustPut(t, s, c.kind.full(id, 0))
	versions := make([]T, contractConcurrency)
	for v := range versions {
		versions[v] = c.kind.full(id, v)
	}
	whole := func(r T) bool {
		return slices.ContainsFunc(versions, func(v T) bool { return len(diff(r, v)) == 0 })
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var problems []string
	report := func(p string) {
		mu.Lock()
		defer mu.Unlock()
		problems = append(problems, p)
	}
	for _, v := range versions {
		wg.Go(func() {
			if err := s.put(context.Background(), v); err != nil {
				report("Put: " + err.Error())
			}
		})
		wg.Go(func() {
			r, ok, err := c.lookup(context.Background(), s, id)
			switch {
			case err != nil:
				report("read: " + err.Error())
			case !ok:
				report("read: not found while being replaced")
			case !whole(r):
				report("read a record that's no one Put's whole")
			}
		})
	}
	wg.Wait()
	for _, p := range problems {
		t.Error(p)
	}
	if r := c.mustFind(t, s, id); !whole(r) {
		t.Error("after concurrent Puts, the record is no one Put's whole")
	}
}

// concurrentMixed: Puts, lookups, listings and Deletes of different
// records concurrently fail only as the interface allows; run with
// -race.
func (c recordContract[T]) concurrentMixed(t *testing.T, s recordStore[T]) {
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 4*contractConcurrency)
	for i := range contractConcurrency {
		id := fmt.Sprintf("rec-%02d", i)
		wg.Go(func() {
			if err := s.put(ctx, c.kind.full(id, i)); err != nil {
				errs <- err
				return
			}
			if _, _, err := c.lookup(ctx, s, id); err != nil {
				errs <- err
			}
			if i%2 == 0 {
				errs <- s.del(ctx, id)
			}
		})
		wg.Go(func() {
			_, err := s.list(ctx)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent use: %v", err)
		}
	}
	all, err := s.list(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != contractConcurrency/2 {
		t.Errorf("List after concurrent use = %d records, want the %d not deleted", len(all), contractConcurrency/2)
	}
}

// cancelled: given a cancelled context, a call either completes or
// fails with the context's error, changing nothing.
func (c recordContract[T]) cancelled(t *testing.T, s recordStore[T]) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := c.kind.full("rec-1", 1)
	if err := s.put(ctx, r); err != nil {
		expectCanceled(t, "Put", err)
		c.mustBeGone(t, s, "rec-1")
		c.mustPut(t, s, r)
	} else {
		expectEqual(t, "after Put with a cancelled context", c.mustFind(t, s, "rec-1"), r)
	}
	if s.get != nil {
		if got, err := s.get(ctx, "rec-1"); err != nil {
			expectCanceled(t, "Get", err)
		} else {
			expectEqual(t, "Get with a cancelled context", got, r)
		}
	}
	if all, err := s.list(ctx); err != nil {
		expectCanceled(t, "List", err)
	} else if len(all) != 1 {
		t.Errorf("List with a cancelled context = %d records, want 1", len(all))
	}
	if err := s.del(ctx, "rec-1"); err != nil {
		expectCanceled(t, "Delete", err)
		c.mustFind(t, s, "rec-1")
	} else {
		c.mustBeGone(t, s, "rec-1")
	}
}

// expectCanceled fails t unless err is the cancelled context's.
func expectCanceled(t *testing.T, call string, err error) {
	t.Helper()
	if !errors.Is(err, context.Canceled) {
		t.Errorf("%s with a cancelled context = %v; want success, or an error wrapping context.Canceled", call, err)
	}
}

// durableConsistent: Durable gives one answer, whatever is stored —
// walletflow checks it once, at New.
func (c recordContract[T]) durableConsistent(t *testing.T, s recordStore[T]) {
	if s.durable == nil {
		t.Skip("the interface has no Durable")
	}
	before := s.durable()
	c.mustPut(t, s, c.kind.full("rec-1", 1))
	if after := s.durable(); after != before {
		t.Errorf("Durable = %v before a Put, %v after", before, after)
	}
}
