// Package statuslisttest holds a reusable contract test for
// statuslist.IndexStore, for a caller testing its own implementation.
// It imports "testing": import it only from _test.go files.
package statuslisttest

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// The lists the contract reserves indices of.
const (
	listA = "https://issuer.example/statuslists/a"
	listB = "https://issuer.example/statuslists/b"
)

// TestIndexStoreContract checks that the stores newStore returns
// behave as statuslist.IndexStore requires. newStore returns a new,
// empty store each time it's called.
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
