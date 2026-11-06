package statuslist

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// singleStore is a MemoryIndexStore that isn't a BatchIndexStore, so
// AllocateN reserves one index at a time.
type singleStore struct{ m MemoryIndexStore }

func (s *singleStore) Reserve(ctx context.Context, uri string, idx uint64) error {
	return s.m.Reserve(ctx, uri, idx)
}
func (s *singleStore) Reserved(ctx context.Context, uri string) (int, error) {
	return s.m.Reserved(ctx, uri)
}
func (s *singleStore) SetStatus(ctx context.Context, uri string, idx uint64, status StatusType) error {
	return s.m.SetStatus(ctx, uri, idx, status)
}
func (s *singleStore) Status(ctx context.Context, uri string, idx uint64) (StatusType, error) {
	return s.m.Status(ctx, uri, idx)
}
func (s *singleStore) Statuses(ctx context.Context, uri string, size int) ([]uint8, error) {
	return s.m.Statuses(ctx, uri, size)
}
func (s *singleStore) Delete(ctx context.Context, uri string) error { return s.m.Delete(ctx, uri) }

// batchCountingStore counts ReserveEach and Reserved calls.
type batchCountingStore struct {
	countingStore
	reserveEach int
}

func (s *batchCountingStore) ReserveEach(ctx context.Context, uri string, idxs []uint64) ([]uint64, error) {
	s.mu.Lock()
	s.reserveEach++
	s.mu.Unlock()
	return s.MemoryIndexStore.ReserveEach(ctx, uri, idxs)
}

// TestAllocateN: a batch's indices are distinct, never handed out
// before, taken from each list only up to its FillLimit and then from
// the next, counting each list once and, with a BatchIndexStore,
// reserving each list's share in one call; a store without ReserveEach
// gets one Reserve per index, with the same result.
func TestAllocateN(t *testing.T) {
	ctx := context.Background()
	t.Run("batch", func(t *testing.T) {
		store := &batchCountingStore{}
		a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 64}}, Store: store, Rand: seeded(), FillLimit: 0.5}
		first, err := a.Allocate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		refs, err := a.AllocateN(ctx, 10)
		if err != nil {
			t.Fatal(err)
		}
		checkBatch(t, append(refs, first), map[string]int{allocListA: 8, allocListB: 3})
		if got := store.count(allocListA); got != 2 {
			t.Errorf("list A counted %d times, want 2 (Allocate, AllocateN)", got)
		}
		if got := store.count(allocListB); got != 1 {
			t.Errorf("list B counted %d times, want 1", got)
		}
		if store.reserveEach < 2 || store.reserveEach > 4 {
			t.Errorf("%d ReserveEach calls for two lists", store.reserveEach)
		}
	})
	t.Run("single", func(t *testing.T) {
		a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 64}}, Store: &singleStore{}, Rand: seeded()}
		refs, err := a.AllocateN(ctx, 11)
		if err != nil {
			t.Fatal(err)
		}
		checkBatch(t, refs, map[string]int{allocListA: 8, allocListB: 3})
	})
}

// checkBatch fails unless refs are distinct and spread over the lists
// as want says.
func checkBatch(t *testing.T, refs []StatusListRef, want map[string]int) {
	t.Helper()
	seen := map[StatusListRef]bool{}
	got := map[string]int{}
	for _, ref := range refs {
		if seen[ref] {
			t.Fatalf("%+v handed out twice", ref)
		}
		seen[ref] = true
		got[ref.URI]++
	}
	for uri, n := range want {
		if got[uri] != n {
			t.Fatalf("%d indices of %s, want %d (all: %v)", got[uri], uri, n, got)
		}
	}
}

// TestAllocateN_RetriesCollisions: an index already reserved, or drawn
// twice in one batch, is drawn again.
func TestAllocateN_RetriesCollisions(t *testing.T) {
	ctx := context.Background()
	for _, store := range []IndexStore{&MemoryIndexStore{}, &singleStore{}} {
		if err := store.Reserve(ctx, allocListA, 3); err != nil {
			t.Fatal(err)
		}
		a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: store, Rand: draws(3, 5, 5, 3, 6)}
		refs, err := a.AllocateN(ctx, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(refs) != 2 || refs[0].Idx == refs[1].Idx || refs[0].Idx == 3 || refs[1].Idx == 3 {
			t.Fatalf("%T: got %+v", store, refs)
		}
	}
}

// TestAllocateN_Full: a batch that the lists can't hold fails with
// ErrListsFull; one that fits after a new list is appended succeeds.
func TestAllocateN_Full(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 16}}, Store: &MemoryIndexStore{}, Rand: seeded()}
	if _, err := a.AllocateN(ctx, 9); !errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v, want ErrListsFull", err)
	}
	a.Lists = append(a.Lists, AllocatorList{URI: allocListB, Size: 64})
	if _, err := a.AllocateN(ctx, 9); err != nil {
		t.Fatal(err)
	}
}

// TestAllocateN_Refuses: n outside 1 to MaxAllocateN, a store error,
// and a store reporting an index it wasn't asked for are refused.
func TestAllocateN_Refuses(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 4096}}, Store: &MemoryIndexStore{}}
	for _, n := range []int{0, -1, MaxAllocateN + 1} {
		if _, err := a.AllocateN(ctx, n); err == nil {
			t.Errorf("AllocateN(%d) succeeded", n)
		}
	}
	a.Store = &lyingStore{}
	if _, err := a.AllocateN(ctx, 2); err == nil {
		t.Fatal("accepted an index the store wasn't asked for")
	}
	a.Store = &erringBatchStore{}
	if _, err := a.AllocateN(ctx, 2); !errors.Is(err, errStore) {
		t.Fatalf("got %v", err)
	}
}

type lyingStore struct{ MemoryIndexStore }

func (*lyingStore) ReserveEach(_ context.Context, _ string, idxs []uint64) ([]uint64, error) {
	return []uint64{idxs[0], idxs[0]}, nil
}

type erringBatchStore struct{ MemoryIndexStore }

func (*erringBatchStore) ReserveEach(context.Context, string, []uint64) ([]uint64, error) {
	return nil, errStore
}

// TestAllocateN_Concurrent: concurrent batches never share an index.
func TestAllocateN_Concurrent(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 256}, {URI: allocListB, Size: 256}}, Store: &MemoryIndexStore{}}
	const batches, n = 20, 10
	var mu sync.Mutex
	var all []StatusListRef
	var wg sync.WaitGroup
	for range batches {
		wg.Go(func() {
			refs, err := a.AllocateN(ctx, n)
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			all = append(all, refs...)
			mu.Unlock()
		})
	}
	wg.Wait()
	if len(all) != batches*n {
		t.Fatalf("%d allocations, want %d", len(all), batches*n)
	}
	checkBatch(t, all, nil)
}

// AllocateN counts a list afresh every 64 indices it reserves in it, so
// that concurrent batches each pass its FillLimit by at most that many,
// and a batch of 64 or fewer still counts it once.
func TestAllocateNCountsPerChunk(t *testing.T) {
	ctx := context.Background()
	store := &batchCountingStore{}
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 1 << 12}}, Store: store, Rand: seeded()}
	if _, err := a.AllocateN(ctx, 64); err != nil {
		t.Fatal(err)
	}
	if got := store.count(allocListA); got != 1 {
		t.Errorf("a batch of 64 counted the list %d times, want 1", got)
	}
	refs, err := a.AllocateN(ctx, 200)
	if err != nil {
		t.Fatal(err)
	}
	checkBatch(t, refs, map[string]int{allocListA: 200})
	if got := store.count(allocListA) - 1; got != 4 {
		t.Errorf("a batch of 200 counted the list %d times, want 4 (64, 64, 64, 8)", got)
	}
}
