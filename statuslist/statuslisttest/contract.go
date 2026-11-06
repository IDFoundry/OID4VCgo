// Package statuslisttest holds reusable contract tests for
// statuslist.IndexStore and statuslist.TokenStore, for a caller testing
// its own implementation.
// It imports "testing": import it only from _test.go files.
package statuslisttest

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// The lists the contract reserves indices of.
const (
	listA = "https://issuer.example/statuslists/a"
	listB = "https://issuer.example/statuslists/b"
)

// TestIndexStoreContract checks that the stores newStore returns
// behave as statuslist.IndexStore requires and, for a store that is
// also a statuslist.BatchIndexStore, as ReserveEach requires. newStore
// returns a new, empty store each time it's called.
func TestIndexStoreContract(t *testing.T, newStore func(t *testing.T) statuslist.IndexStore) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, statuslist.IndexStore)
	}{
		{"ReserveOnce", reserveOnce},
		{"StatusesRoundTrip", statusesRoundTrip},
		{"NotReserved", notReserved},
		{"DeleteForgetsOneList", deleteForgetsOneList},
		{"DeleteIsIdempotent", deleteIsIdempotent},
		{"ReserveEach", reserveEach},
		{"ReserveEachConcurrent", reserveEachConcurrent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

func mustReserve(t *testing.T, s statuslist.IndexStore, uri string, idx uint64) {
	t.Helper()
	if err := s.Reserve(context.Background(), uri, idx); err != nil {
		t.Fatalf("Reserve(%s, %d): %v", uri, idx, err)
	}
}

func mustSetStatus(t *testing.T, s statuslist.IndexStore, uri string, idx uint64, status statuslist.StatusType) {
	t.Helper()
	if err := s.SetStatus(context.Background(), uri, idx, status); err != nil {
		t.Fatalf("SetStatus(%s, %d): %v", uri, idx, err)
	}
}

func mustDelete(t *testing.T, s statuslist.IndexStore, uri string) {
	t.Helper()
	if err := s.Delete(context.Background(), uri); err != nil {
		t.Fatalf("Delete(%s): %v", uri, err)
	}
}

// expectReserved checks the list at uri has want indices reserved.
func expectReserved(t *testing.T, s statuslist.IndexStore, uri string, want int) {
	t.Helper()
	if n, err := s.Reserved(context.Background(), uri); err != nil || n != want {
		t.Fatalf("Reserved(%s) = %d, %v; want %d", uri, n, err, want)
	}
}

// expectStatus checks the status of idx in the list at uri.
func expectStatus(t *testing.T, s statuslist.IndexStore, uri string, idx uint64, want statuslist.StatusType) {
	t.Helper()
	if got, err := s.Status(context.Background(), uri, idx); err != nil || got != want {
		t.Fatalf("Status(%s, %d) = %v, %v; want %v", uri, idx, got, err, want)
	}
}

// expectStatuses checks the statuses of the list at uri, of
// len(want) indices.
func expectStatuses(t *testing.T, s statuslist.IndexStore, uri string, want []uint8) {
	t.Helper()
	got, err := s.Statuses(context.Background(), uri, len(want))
	if err != nil || string(got) != string(want) {
		t.Fatalf("Statuses(%s, %d) = %v, %v; want %v", uri, len(want), got, err, want)
	}
}

func reserveOnce(t *testing.T, s statuslist.IndexStore) {
	expectReserved(t, s, listA, 0)
	mustReserve(t, s, listA, 0)
	mustReserve(t, s, listA, 7)
	if err := s.Reserve(context.Background(), listA, 7); !errors.Is(err, statuslist.ErrIndexTaken) {
		t.Fatalf("Reserve of a reserved index = %v, want ErrIndexTaken", err)
	}
	// The same index of another list is another index.
	mustReserve(t, s, listB, 7)
	expectReserved(t, s, listA, 2)
	expectReserved(t, s, listB, 1)
}

func statusesRoundTrip(t *testing.T, s statuslist.IndexStore) {
	for _, idx := range []uint64{1, 3, 6} {
		mustReserve(t, s, listA, idx)
	}
	expectStatus(t, s, listA, 3, statuslist.StatusValid)
	mustSetStatus(t, s, listA, 1, statuslist.StatusInvalid)
	mustSetStatus(t, s, listA, 6, statuslist.StatusSuspended)
	expectStatus(t, s, listA, 6, statuslist.StatusSuspended)
	expectStatuses(t, s, listA, []uint8{0, 1, 0, 0, 0, 0, 2, 0})
	// Reserving the index again doesn't reset its status.
	if err := s.Reserve(context.Background(), listA, 6); !errors.Is(err, statuslist.ErrIndexTaken) {
		t.Fatalf("Reserve of a reserved index = %v, want ErrIndexTaken", err)
	}
	expectStatus(t, s, listA, 6, statuslist.StatusSuspended)
	if _, err := s.Statuses(context.Background(), listA, 4); err == nil {
		t.Fatal("Statuses accepted a size a reservation lies outside")
	}
	expectStatuses(t, s, listB, make([]uint8, 8))
}

func notReserved(t *testing.T, s statuslist.IndexStore) {
	mustReserve(t, s, listA, 1)
	for name, c := range map[string]struct {
		uri string
		idx uint64
	}{"unreserved index": {listA, 2}, "unseen list": {listB, 1}} {
		if err := s.SetStatus(context.Background(), c.uri, c.idx, statuslist.StatusInvalid); !errors.Is(err, statuslist.ErrIndexNotReserved) {
			t.Errorf("%s: SetStatus = %v, want ErrIndexNotReserved", name, err)
		}
		if _, err := s.Status(context.Background(), c.uri, c.idx); !errors.Is(err, statuslist.ErrIndexNotReserved) {
			t.Errorf("%s: Status = %v, want ErrIndexNotReserved", name, err)
		}
	}
	expectReserved(t, s, listB, 0)
}

func deleteForgetsOneList(t *testing.T, s statuslist.IndexStore) {
	mustReserve(t, s, listA, 1)
	mustReserve(t, s, listA, 5)
	mustSetStatus(t, s, listA, 5, statuslist.StatusSuspended)
	mustReserve(t, s, listB, 5)
	mustSetStatus(t, s, listB, 5, statuslist.StatusInvalid)

	mustDelete(t, s, listA)
	expectReserved(t, s, listA, 0)
	if _, err := s.Status(context.Background(), listA, 5); !errors.Is(err, statuslist.ErrIndexNotReserved) {
		t.Fatalf("Status of a deleted list's index = %v, want ErrIndexNotReserved", err)
	}
	expectStatuses(t, s, listA, make([]uint8, 8))

	// The other list keeps its reservations and statuses.
	expectReserved(t, s, listB, 1)
	expectStatus(t, s, listB, 5, statuslist.StatusInvalid)

	// The deleted list's indices are reserved afresh.
	mustReserve(t, s, listA, 5)
	expectReserved(t, s, listA, 1)
	expectStatus(t, s, listA, 5, statuslist.StatusValid)
}

func deleteIsIdempotent(t *testing.T, s statuslist.IndexStore) {
	mustDelete(t, s, listA) // never seen
	mustReserve(t, s, listA, 3)
	mustDelete(t, s, listA)
	mustDelete(t, s, listA)
	expectReserved(t, s, listA, 0)
}

// batchStore returns s as a statuslist.BatchIndexStore, skipping the
// test if it isn't one.
func batchStore(t *testing.T, s statuslist.IndexStore) statuslist.BatchIndexStore {
	t.Helper()
	b, ok := s.(statuslist.BatchIndexStore)
	if !ok {
		t.Skip("not a statuslist.BatchIndexStore")
	}
	return b
}

func reserveEach(t *testing.T, s statuslist.IndexStore) {
	b := batchStore(t, s)
	ctx := context.Background()
	mustReserve(t, s, listA, 7)
	got, err := b.ReserveEach(ctx, listA, []uint64{9, 7, 3})
	if err != nil {
		t.Fatalf("ReserveEach: %v", err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []uint64{3, 9}) {
		t.Fatalf("ReserveEach reserved %v, want [3 9]: 7 was reserved", got)
	}
	expectReserved(t, s, listA, 3)
	if err := s.Reserve(ctx, listA, 3); !errors.Is(err, statuslist.ErrIndexTaken) {
		t.Fatalf("Reserve of an index ReserveEach reserved = %v, want ErrIndexTaken", err)
	}
	expectStatuses(t, s, listA, []uint8{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	mustSetStatus(t, s, listA, 9, statuslist.StatusInvalid)
	expectStatus(t, s, listA, 9, statuslist.StatusInvalid)
	// Another list's indices are other indices.
	if got, err := b.ReserveEach(ctx, listB, []uint64{7, 3}); err != nil || len(got) != 2 {
		t.Fatalf("ReserveEach of another list = %v, %v", got, err)
	}
	expectReserved(t, s, listB, 2)
	if got, err := b.ReserveEach(ctx, listA, []uint64{3, 7, 9}); err != nil || len(got) != 0 {
		t.Fatalf("ReserveEach of reserved indices = %v, %v; want none", got, err)
	}
	expectReserved(t, s, listA, 3)
}

// reserveEachConcurrent: of concurrent ReserveEach calls naming
// overlapping sets of indices, each index is reserved by exactly one.
func reserveEachConcurrent(t *testing.T, s statuslist.IndexStore) {
	b := batchStore(t, s)
	const callers, n = 8, 32
	var mu sync.Mutex
	counts := map[uint64]int{}
	var wg sync.WaitGroup
	for c := range callers {
		wg.Go(func() {
			idxs := make([]uint64, n)
			for i := range idxs {
				idxs[i] = uint64((i*(c+1) + c) % n) // #nosec G115 -- small and non-negative
			}
			slices.Sort(idxs)
			idxs = slices.Compact(idxs)
			got, err := b.ReserveEach(context.Background(), listA, idxs)
			if err != nil {
				t.Errorf("ReserveEach: %v", err)
				return
			}
			mu.Lock()
			for _, idx := range got {
				counts[idx]++
			}
			mu.Unlock()
		})
	}
	wg.Wait()
	for idx, k := range counts {
		if k != 1 {
			t.Fatalf("index %d reserved by %d callers", idx, k)
		}
	}
	reserved, err := s.Reserved(context.Background(), listA)
	if err != nil || reserved != len(counts) {
		t.Fatalf("Reserved = %d, %v; ReserveEach reported %d", reserved, err, len(counts))
	}
}
