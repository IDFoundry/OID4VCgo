package statuslist

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"math"
	mrand "math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

const (
	allocListA = "https://issuer.example/statuslists/1"
	allocListB = "https://issuer.example/statuslists/2"
)

// draws is a Rand returning each value as the next 64 random bits.
func draws(values ...uint64) *bytes.Reader {
	var buf []byte
	for _, v := range values {
		buf = binary.BigEndian.AppendUint64(buf, v)
	}
	return bytes.NewReader(buf)
}

// seeded is a deterministic Rand for tests that draw many indices.
func seeded() *mrand.ChaCha8 {
	return mrand.NewChaCha8([32]byte{1, 2, 3})
}

// TestRandomIndex_Uniform: every draw is in range, including for a
// size that isn't a power of two (so rejection, not a mask alone, keeps
// it there), and the draws are spread evenly.
func TestRandomIndex_Uniform(t *testing.T) {
	for _, size := range []uint64{1, 2, 24, 64, 1000} {
		r := seeded()
		const perIndex = 400
		counts := make([]int, size)
		for range int(size) * perIndex {
			idx, err := randomIndex(r, size)
			if err != nil {
				t.Fatal(err)
			}
			if idx >= size {
				t.Fatalf("size %d: drew %d", size, idx)
			}
			counts[idx]++
		}
		// Chi-squared against uniform: its mean is size-1 and its
		// standard deviation sqrt(2(size-1)); allow six of them.
		chi := 0.0
		for _, c := range counts {
			d := float64(c - perIndex)
			chi += d * d / perIndex
		}
		if limit := float64(size-1) + 6*math.Sqrt(2*float64(size-1)); chi > limit {
			t.Errorf("size %d: chi-squared %.1f over %.1f: %v", size, chi, limit, counts)
		}
	}
}

// TestRandomIndex_RejectsOverSize: a draw of size or more under the
// mask is drawn again, not reduced, so the low indices aren't likelier.
func TestRandomIndex_RejectsOverSize(t *testing.T) {
	// Size 24 keeps 5 bits: 30 and 25 are rejected, 7 is taken.
	idx, err := randomIndex(draws(30, 25, 7), 24)
	if err != nil || idx != 7 {
		t.Fatalf("got %d, %v; want 7", idx, err)
	}
	if _, err := randomIndex(draws(), 24); err == nil {
		t.Fatal("an exhausted reader drew an index")
	}
	// The full 64-bit range is used for a size over 2^63.
	if idx, err := randomIndex(draws(math.MaxUint64, 5), math.MaxUint64); err != nil || idx != 5 {
		t.Fatalf("got %d, %v; want 5", idx, err)
	}
}

// TestAllocator_RetriesCollisions: an index already reserved is drawn
// again, not handed out twice.
func TestAllocator_RetriesCollisions(t *testing.T) {
	ctx := context.Background()
	store := &MemoryIndexStore{}
	if err := store.Reserve(ctx, allocListA, 3); err != nil {
		t.Fatal(err)
	}
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: store, Rand: draws(3, 3, 5)}
	ref, err := a.Allocate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ref != (StatusListRef{Idx: 5, URI: allocListA}) {
		t.Fatalf("got %+v", ref)
	}
}

// TestAllocator_RollsOverAndFills: a list is used until FillLimit of
// it is reserved, then the next, and ErrListsFull follows the last.
// No index is handed out twice.
func TestAllocator_RollsOverAndFills(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{
		Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 32}},
		Store: &MemoryIndexStore{}, Rand: seeded(), FillLimit: 0.25,
	}
	seen := map[StatusListRef]bool{}
	for i := range 4 + 8 {
		ref, err := a.Allocate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		wantURI := allocListA
		if i >= 4 {
			wantURI = allocListB
		}
		if ref.URI != wantURI {
			t.Fatalf("allocation %d went to %s, want %s", i, ref.URI, wantURI)
		}
		if seen[ref] {
			t.Fatalf("%+v handed out twice", ref)
		}
		seen[ref] = true
	}
	if _, err := a.Allocate(ctx); !errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v, want ErrListsFull", err)
	}
	// A new list appended takes the next allocation.
	a.Lists = append(a.Lists, AllocatorList{URI: "https://issuer.example/statuslists/3", Size: 8})
	if ref, err := a.Allocate(ctx); err != nil || ref.URI != "https://issuer.example/statuslists/3" {
		t.Fatalf("got %+v, %v", ref, err)
	}
}

// reservedErrStore fails Reserved.
type reservedErrStore struct{ MemoryIndexStore }

func (*reservedErrStore) Reserved(context.Context, string) (int, error) { return 0, errStore }

// TestAllocator_Fill: Fill reports each list's limit and reserved
// indices, in order, as Allocate fills them; a list is Full at its
// limit, with no Free indices.
func TestAllocator_Fill(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{
		Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 32}},
		Store: &MemoryIndexStore{}, Rand: seeded(), FillLimit: 0.25,
	}
	fill := func() []ListFill {
		t.Helper()
		f, err := a.Fill(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	want := []ListFill{{URI: allocListA, Size: 16, Limit: 4}, {URI: allocListB, Size: 32, Limit: 8}}
	if got := fill(); !slices.Equal(got, want) {
		t.Fatalf("an unused Allocator's fill = %+v, want %+v", got, want)
	}
	for range 4 + 3 {
		if _, err := a.Allocate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	got := fill()
	if got[0].Reserved != 4 || !got[0].Full() || got[0].Free() != 0 ||
		got[1].Reserved != 3 || got[1].Full() || got[1].Free() != 5 {
		t.Fatalf("after 7 allocations, fill = %+v", got)
	}
	if f := (ListFill{Limit: 4, Reserved: 6}); !f.Full() || f.Free() != 0 {
		t.Fatalf("a list past its limit: Full %v, Free %d", f.Full(), f.Free())
	}

	a.Store = &reservedErrStore{}
	if _, err := a.Fill(ctx); !errors.Is(err, errStore) {
		t.Fatalf("Fill with a failing store = %v", err)
	}
	if _, err := (&Allocator{}).Fill(ctx); err == nil {
		t.Fatal("Fill of an Allocator without lists or store succeeded")
	}
}

// TestAllocator_DefaultFillLimit: half a list is handed out by
// default, every index of it distinct.
func TestAllocator_DefaultFillLimit(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 64}}, Store: &MemoryIndexStore{}}
	seen := map[uint64]bool{}
	for range 32 {
		ref, err := a.Allocate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seen[ref.Idx] || ref.Idx >= 64 {
			t.Fatalf("index %d reused or out of range", ref.Idx)
		}
		seen[ref.Idx] = true
	}
	if _, err := a.Allocate(ctx); !errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v, want ErrListsFull", err)
	}
}

// TestAllocator_GivesUpOnNonRandom: a Rand that keeps drawing reserved
// indices ends in an error, not a loop or ErrListsFull.
func TestAllocator_GivesUpOnNonRandom(t *testing.T) {
	ctx := context.Background()
	store := &MemoryIndexStore{}
	if err := store.Reserve(ctx, allocListA, 0); err != nil {
		t.Fatal(err)
	}
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: store, Rand: bytes.NewReader(make([]byte, 8*maxAllocateAttempts))}
	_, err := a.Allocate(ctx)
	if err == nil || errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v", err)
	}
	a.Rand = draws()
	if _, err := a.Allocate(ctx); err == nil {
		t.Fatal("allocated with an empty Rand")
	}
}

// failingStore fails Reserve, and returns the wrong number of
// statuses.
type failingStore struct{ MemoryIndexStore }

var errStore = errors.New("store down")

func (*failingStore) Reserve(context.Context, string, uint64) error { return errStore }
func (*failingStore) Reserved(context.Context, string) (int, error) { return 0, nil }
func (*failingStore) Statuses(context.Context, string, int) ([]uint8, error) {
	return make([]uint8, 3), nil
}

// TestAllocator_StoreErrors: a store error is returned, not retried as
// a collision; a store returning the wrong number of statuses is
// refused.
func TestAllocator_StoreErrors(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: &failingStore{}}
	if _, err := a.Allocate(ctx); !errors.Is(err, errStore) {
		t.Fatalf("got %v", err)
	}
	if _, err := a.Statuses(allocListA)(ctx); err == nil {
		t.Fatal("accepted 3 statuses for a list of 8")
	}
}

// TestAllocator_StatusRoundTrip: a status SetStatus sets is what a
// Publisher's token, read with Check, says; an index never handed out
// reads VALID in the list but is refused by SetStatus.
func TestAllocator_StatusRoundTrip(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 1024}}, Store: &MemoryIndexStore{}, Bits: Bits2}
	revoked := ok(a.Allocate(ctx))(t)
	suspended := ok(a.Allocate(ctx))(t)
	valid := ok(a.Allocate(ctx))(t)
	if err := a.SetStatus(ctx, revoked, StatusInvalid); err != nil {
		t.Fatal(err)
	}
	if err := a.SetStatus(ctx, suspended, StatusSuspended); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Status(ctx, suspended); err != nil || got != StatusSuspended {
		t.Fatalf("Status: %v, %v", got, err)
	}

	ca, caKey := testcert.CA(t, "status CA")
	cert, key := testcert.Leaf(t, "status signer", ca, caKey)
	p := &Publisher{URI: allocListA, Signer: key, Chain: []*x509.Certificate{cert}, Statuses: a.Statuses(allocListA), Bits: Bits2}
	token := ok(p.Token(ctx, false))(t)

	var unreserved uint64
	for unreserved == revoked.Idx || unreserved == suspended.Idx || unreserved == valid.Idx {
		unreserved++
	}
	for ref, want := range map[StatusListRef]StatusType{
		revoked: StatusInvalid, suspended: StatusSuspended, valid: StatusValid,
		{Idx: unreserved, URI: allocListA}: StatusValid,
	} {
		got, _, err := Check(string(token), &key.PublicKey, jose.ES256, ref, VerifyOptions{UnboundSigner: AnyListSigner})
		if err != nil || got != want {
			t.Errorf("index %d: %v, %v; want %v", ref.Idx, got, err, want)
		}
	}

	if err := a.SetStatus(ctx, StatusListRef{Idx: unreserved, URI: allocListA}, StatusInvalid); !errors.Is(err, ErrIndexNotReserved) {
		t.Errorf("SetStatus on an unreserved index: %v", err)
	}
	if got, err := a.Status(ctx, StatusListRef{Idx: unreserved, URI: allocListA}); !errors.Is(err, ErrIndexNotReserved) || got != StatusInvalid {
		t.Errorf("Status on an unreserved index: %v, %v", got, err)
	}
}

// TestAllocator_SetStatusRefuses: a ref outside the Allocator's lists
// and a status that doesn't fit Bits are refused.
func TestAllocator_SetStatusRefuses(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: &MemoryIndexStore{}}
	ref := ok(a.Allocate(ctx))(t)
	for name, tc := range map[string]struct {
		ref    StatusListRef
		status StatusType
	}{
		"other list":        {StatusListRef{Idx: ref.Idx, URI: allocListB}, StatusInvalid},
		"index past size":   {StatusListRef{Idx: 8, URI: allocListA}, StatusInvalid},
		"status over Bits1": {ref, StatusSuspended},
	} {
		if err := a.SetStatus(ctx, tc.ref, tc.status); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := a.Statuses(allocListB)(ctx); err == nil {
		t.Error("Statuses for a list not in Lists")
	}
	if got := ok(a.Status(ctx, ref))(t); got != StatusValid {
		t.Errorf("status changed to %v", got)
	}
}

// TestAllocator_Concurrent: concurrent Allocate calls hand out
// distinct indices.
func TestAllocator_Concurrent(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 256}, {URI: allocListB, Size: 256}}, Store: &MemoryIndexStore{}}
	const n = 200
	refs := make(chan StatusListRef, n)
	var wg sync.WaitGroup
	for range n {
		wg.Go(func() {
			ref, err := a.Allocate(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			refs <- ref
		})
	}
	wg.Wait()
	close(refs)
	seen := map[StatusListRef]bool{}
	for ref := range refs {
		if seen[ref] {
			t.Fatalf("%+v handed out twice", ref)
		}
		seen[ref] = true
	}
	if len(seen) != n {
		t.Fatalf("%d allocations, want %d", len(seen), n)
	}
}

// countingStore counts the Reserved calls for each list.
type countingStore struct {
	MemoryIndexStore
	mu     sync.Mutex
	counts map[string]int
}

func (s *countingStore) Reserved(ctx context.Context, uri string) (int, error) {
	s.mu.Lock()
	if s.counts == nil {
		s.counts = map[string]int{}
	}
	s.counts[uri]++
	s.mu.Unlock()
	return s.MemoryIndexStore.Reserved(ctx, uri)
}

// count is how many times Reserved was called for the list at uri.
func (s *countingStore) count(uri string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counts[uri]
}

// TestAllocator_SkipsFullLists: once Allocate finds a list full, it
// counts that list's reserved indices no more, and once it has found
// every list full, it returns ErrListsFull without asking the store.
func TestAllocator_SkipsFullLists(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{}
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 16}}, Store: store, Rand: seeded()}
	for range 8 + 8 {
		ok(a.Allocate(ctx))(t)
	}
	// Eight allocations in A, then one finding it full.
	if n := store.count(allocListA); n != 9 {
		t.Fatalf("Reserved(A) called %d times, want 9", n)
	}
	if _, err := a.Allocate(ctx); !errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v, want ErrListsFull", err)
	}
	before := store.count(allocListA) + store.count(allocListB)
	for range 3 {
		if _, err := a.Allocate(ctx); !errors.Is(err, ErrListsFull) {
			t.Fatalf("got %v, want ErrListsFull", err)
		}
	}
	if after := store.count(allocListA) + store.count(allocListB); after != before {
		t.Fatalf("Reserved called %d more times once every list was known full", after-before)
	}
	// SetStatus and Statuses still serve a full list.
	if _, err := a.Statuses(allocListA)(ctx); err != nil {
		t.Fatal(err)
	}
}

// TestAllocator_ListFilledElsewhere: a list another Allocator — in
// another process — fills is found full when next counted, and
// skipped from then on.
func TestAllocator_ListFilledElsewhere(t *testing.T) {
	ctx := context.Background()
	store := &countingStore{}
	lists := []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 16}}
	here := &Allocator{Lists: lists, Store: store, Rand: seeded()}
	elsewhere := &Allocator{Lists: lists, Store: store, Rand: mrand.NewChaCha8([32]byte{4})}
	if ref := ok(here.Allocate(ctx))(t); ref.URI != allocListA {
		t.Fatalf("first allocation in %s", ref.URI)
	}
	for range 7 {
		if ref := ok(elsewhere.Allocate(ctx))(t); ref.URI != allocListA {
			t.Fatalf("allocation elsewhere in %s", ref.URI)
		}
	}
	for range 4 {
		if ref := ok(here.Allocate(ctx))(t); ref.URI != allocListB {
			t.Fatalf("allocation after A filled elsewhere in %s, want B", ref.URI)
		}
	}
	// Here once finding room, elsewhere seven times, here once finding
	// it full.
	if n := store.count(allocListA); n != 9 {
		t.Fatalf("Reserved(A) called %d times, want 9", n)
	}
}

// TestAllocator_ChangedSettings: settings once validated are validated
// again when they change, and a raised FillLimit reopens a list found
// full at the lower one.
func TestAllocator_ChangedSettings(t *testing.T) {
	ctx := context.Background()
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 16}, {URI: allocListB, Size: 16}}, Store: &MemoryIndexStore{}, Rand: seeded(), FillLimit: 0.25}
	for range 4 + 1 {
		ok(a.Allocate(ctx))(t)
	}
	checked := a.checked
	ok(a.Allocate(ctx))(t)
	if a.checked != checked || checked.full != 1 {
		t.Fatalf("settings unchanged, validated again, or A not known full: %d", checked.full)
	}
	a.FillLimit = 0.5
	if ref := ok(a.Allocate(ctx))(t); ref.URI != allocListA {
		t.Fatalf("allocation after FillLimit raised in %s, want A", ref.URI)
	}
	a.Lists[1].URI = "http://issuer.example/statuslists/2"
	if _, err := a.Allocate(ctx); err == nil {
		t.Fatal("a list changed in place wasn't validated again")
	}
}

// TestAllocator_ExhaustedListNotFull: a list Allocate gave up drawing
// in isn't taken to be full, nor are those before a full list after it.
func TestAllocator_ExhaustedListNotFull(t *testing.T) {
	ctx := context.Background()
	store := &MemoryIndexStore{}
	if err := store.Reserve(ctx, allocListA, 0); err != nil {
		t.Fatal(err)
	}
	for idx := range uint64(4) {
		if err := store.Reserve(ctx, allocListB, idx); err != nil {
			t.Fatal(err)
		}
	}
	a := &Allocator{Lists: []AllocatorList{{URI: allocListA, Size: 8}, {URI: allocListB, Size: 8}}, Store: store, Rand: bytes.NewReader(make([]byte, 8*maxAllocateAttempts))}
	if _, err := a.Allocate(ctx); err == nil || errors.Is(err, ErrListsFull) {
		t.Fatalf("got %v", err)
	}
	if a.checked.full != 0 {
		t.Fatalf("%d lists taken to be full, want none", a.checked.full)
	}
}

// TestAllocator_Validate: each misconfiguration is refused by every
// method.
func TestAllocator_Validate(t *testing.T) {
	ok := AllocatorList{URI: allocListA, Size: 8}
	store := &MemoryIndexStore{}
	for name, a := range map[string]*Allocator{
		"no store":           {Lists: []AllocatorList{ok}},
		"no lists":           {Store: store},
		"bad bits":           {Lists: []AllocatorList{ok}, Store: store, Bits: 3},
		"negative fill":      {Lists: []AllocatorList{ok}, Store: store, FillLimit: -0.1},
		"fill over max":      {Lists: []AllocatorList{ok}, Store: store, FillLimit: 0.9},
		"fill NaN":           {Lists: []AllocatorList{ok}, Store: store, FillLimit: math.NaN()},
		"zero size":          {Lists: []AllocatorList{{URI: allocListA}}, Store: store},
		"negative size":      {Lists: []AllocatorList{{URI: allocListA, Size: -8}}, Store: store},
		"partial byte":       {Lists: []AllocatorList{{URI: allocListA, Size: 12}}, Store: store},
		"partial byte bits2": {Lists: []AllocatorList{{URI: allocListA, Size: 6}}, Store: store, Bits: Bits2},
		"too large":          {Lists: []AllocatorList{{URI: allocListA, Size: (maxListBytes + 1) * 8}}, Store: store},
		"fill allows none":   {Lists: []AllocatorList{{URI: allocListA, Size: 8}}, Store: store, FillLimit: 0.1},
		"duplicate uri":      {Lists: []AllocatorList{ok, ok}, Store: store},
		"http uri":           {Lists: []AllocatorList{{URI: "http://issuer.example/sl", Size: 8}}, Store: store},
		"relative uri":       {Lists: []AllocatorList{{URI: "/statuslists/1", Size: 8}}, Store: store},
		"fragment":           {Lists: []AllocatorList{{URI: allocListA + "#x", Size: 8}}, Store: store},
		"userinfo":           {Lists: []AllocatorList{{URI: "https://u@issuer.example/sl", Size: 8}}, Store: store},
		"unparseable":        {Lists: []AllocatorList{{URI: "https://issuer.example/%zz", Size: 8}}, Store: store},
	} {
		ctx := context.Background()
		if _, err := a.Allocate(ctx); err == nil || !strings.HasPrefix(err.Error(), "statuslist: ") {
			t.Errorf("%s: Allocate: %v", name, err)
		}
		if err := a.SetStatus(ctx, StatusListRef{URI: allocListA}, StatusInvalid); err == nil {
			t.Errorf("%s: SetStatus accepted", name)
		}
		if _, err := a.Statuses(allocListA)(ctx); err == nil {
			t.Errorf("%s: Statuses accepted", name)
		}
	}
}

// TestMemoryIndexStore: reservations are never released, and Statuses
// refuses a size a reservation lies outside.
func TestMemoryIndexStore(t *testing.T) {
	ctx := context.Background()
	var s MemoryIndexStore
	if n := ok(s.Reserved(ctx, allocListA))(t); n != 0 {
		t.Fatalf("Reserved on an empty store: %d", n)
	}
	if err := s.SetStatus(ctx, allocListA, 1, StatusInvalid); !errors.Is(err, ErrIndexNotReserved) {
		t.Fatalf("SetStatus on an empty store: %v", err)
	}
	if err := s.Reserve(ctx, allocListA, 9); err != nil {
		t.Fatal(err)
	}
	if err := s.SetStatus(ctx, allocListA, 9, StatusInvalid); err != nil {
		t.Fatal(err)
	}
	if err := s.Reserve(ctx, allocListA, 9); !errors.Is(err, ErrIndexTaken) {
		t.Fatalf("second Reserve: %v", err)
	}
	if got := ok(s.Status(ctx, allocListA, 9))(t); got != StatusInvalid {
		t.Fatalf("the second Reserve reset the status to %v", got)
	}
	if err := s.Reserve(ctx, allocListB, 9); err != nil {
		t.Fatalf("the same index in another list: %v", err)
	}
	if got := ok(s.Statuses(ctx, allocListA, 16))(t); len(got) != 16 || got[9] != 1 || bytes.Count(got, []byte{0}) != 15 {
		t.Fatalf("Statuses: %v", got)
	}
	if _, err := s.Statuses(ctx, allocListA, 8); err == nil {
		t.Fatal("Statuses accepted a size a reservation lies outside")
	}
	if _, err := s.Statuses(ctx, allocListA, -1); err == nil {
		t.Fatal("Statuses accepted a negative size")
	}
}

// ok returns a function returning v, or failing its t on err.
func ok[T any](v T, err error) func(*testing.T) T {
	return func(t *testing.T) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
