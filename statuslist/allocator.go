package statuslist

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"net/url"
	"slices"
	"sync"
)

// ErrIndexTaken is what IndexStore.Reserve returns, possibly wrapped,
// for an index already reserved in that list.
var ErrIndexTaken = errors.New("statuslist: the index is already reserved")

// ErrIndexNotReserved is what IndexStore.SetStatus and Status return,
// possibly wrapped, for an index never reserved in that list.
var ErrIndexNotReserved = errors.New("statuslist: the index is not reserved")

// ErrListsFull is what Allocator.Allocate returns when every list has
// reached its fill limit: provision a new list and append it to
// Allocator.Lists.
var ErrListsFull = errors.New("statuslist: every status list is full")

// IndexStore records which indices of which Status Lists an Allocator
// has handed out, and each one's status. An index once reserved stays
// reserved while its list is in use: there is no release of one index,
// since a Referenced Token naming it may still be presented, and
// draft-14 §13.3 has the Status Issuer "prevent any unintended double
// allocation". Delete forgets a whole list once it's retired. A list
// is named by its uri, as in a StatusListRef.
//
// A production store must be durable — an in-memory store forgets its
// reservations on a restart and hands the same indices out again —
// and Reserve must be one atomic check-and-insert, so two concurrent
// calls for the same (uri, idx) can never both succeed, across every
// process sharing the store: in SQL, a single INSERT into a table
// whose primary key is (uri, idx), with a unique-key violation
// reported as ErrIndexTaken. MemoryIndexStore is neither durable nor
// shared between processes.
//
// Every method returns any error other than the sentinels documented
// only when it couldn't answer.
type IndexStore interface {
	// Reserve atomically reserves idx in the list at uri, with status
	// StatusValid. It returns an error wrapping ErrIndexTaken if idx is
	// already reserved there.
	Reserve(ctx context.Context, uri string, idx uint64) error

	// Reserved returns how many indices of the list at uri are
	// reserved — zero for a list it has never seen.
	Reserved(ctx context.Context, uri string) (int, error)

	// SetStatus sets the status of the reserved idx in the list at
	// uri. It returns an error wrapping ErrIndexNotReserved, and
	// changes nothing, if idx isn't reserved there.
	SetStatus(ctx context.Context, uri string, idx uint64, status StatusType) error

	// Status returns the status of the reserved idx in the list at uri,
	// or an error wrapping ErrIndexNotReserved if it isn't reserved
	// there.
	Status(ctx context.Context, uri string, idx uint64) (StatusType, error)

	// Statuses returns the status of every index of the list at uri,
	// which has size indices: a slice of length size, StatusValid (0)
	// at every index not reserved. It returns an error if a reserved
	// index is size or more.
	Statuses(ctx context.Context, uri string, size int) ([]uint8, error)

	// Delete forgets every reservation of the list at uri, and its
	// statuses, as if it had never been seen: Reserved then counts none
	// and Reserve may hand its indices out again. Delete only a list
	// that no Allocator hands indices out of any more, nor will again,
	// and that no Referenced Token still in circulation names: a list
	// retired for good. Deleting a list never seen does nothing. A
	// Delete that fails part-way leaves what it hasn't deleted for
	// another Delete of the list to finish.
	Delete(ctx context.Context, uri string) error
}

// BatchIndexStore is an IndexStore that can reserve several indices of
// one list at once: Allocator.AllocateN reserves a batch's indices with
// one ReserveEach, rather than one Reserve each, when its Store is one.
type BatchIndexStore interface {
	IndexStore

	// ReserveEach reserves, with status StatusValid, each of idxs in the
	// list at uri that isn't reserved yet, and returns those it reserved,
	// in any order; the others were already reserved. Each index is
	// reserved as atomically as by Reserve: of concurrent calls naming
	// it, across every process sharing the store, exactly one reserves
	// it. idxs are distinct. In SQL, one multi-row INSERT … ON CONFLICT
	// DO NOTHING RETURNING the inserted indices.
	ReserveEach(ctx context.Context, uri string, idxs []uint64) ([]uint64, error)
}

// AllocatorList is one Status List an Allocator hands indices out of.
type AllocatorList struct {
	// URI is the list's uri: the Publisher.URI it's served at, and the
	// uri Referenced Tokens name. It must be an absolute https URI.
	URI string

	// Size is how many indices the list has: the length of the slice
	// its Statuses returns. Size times Allocator.Bits must be a
	// multiple of 8, as draft-14 §13.4 recommends, so the packed list
	// has no padding, and the packed list must be no larger than the
	// 16 MiB a Checker decompresses. A larger list hides each index
	// among more, and a Relying Party fetches all of it.
	Size int
}

// DefaultFillLimit is the Allocator.FillLimit used when it's zero.
const DefaultFillLimit = 0.5

// MaxFillLimit is the largest Allocator.FillLimit allowed: above it, a
// random index draw mostly lands on a reserved one, and the reserved
// share of a list starts to reveal how many tokens the issuer has.
const MaxFillLimit = 0.75

// maxAllocateAttempts is how many random indices Allocate draws in one
// list before moving to the next. At MaxFillLimit, every one of them
// colliding has a probability of 0.75^128, about 1e-16.
const maxAllocateAttempts = 128

// maxListBytes is the largest packed list an AllocatorList may have:
// what a Checker decompresses at most.
const maxListBytes = maxDecompressedSize

// Allocator hands out Status List indices to Referenced Tokens at
// random, never handing the same one out twice, as draft-14
// recommends: a sequential index reveals the order, and so the time,
// a token was issued, and how many the issuer has issued (§12.4),
// and an index handed out twice links two tokens' statuses and lets
// revoking one revoke the other (§13.3). Allocate draws an index
// uniformly at random from the first list not yet filled to FillLimit,
// reserves it in Store, and draws again if it was already reserved.
//
// Allocate one index per Referenced Token: in batch issuance, one per
// credential copy, so the copies don't share a status entry a Relying
// Party could link them by (§12.5.1, §13.2); AllocateN allocates a
// batch's at once. Never derive an index from anything about the
// holder or the credential.
//
// Publish each list with a Publisher whose URI is the list's, whose
// Bits is the Allocator's, and whose Statuses is Allocator.Statuses
// for that list; after SetStatus, call the Publisher's Invalidate.
// Keep a full list in Lists: SetStatus and Statuses still need it.
//
// An Allocator remembers its settings once it has validated them, and
// which of its lists it has found full: a list only fills up, so
// Allocate counts a list's reserved indices until it finds the list
// full, whether filled here or by another process, and never again.
// Changing Lists, Bits or FillLimit has the next call validate them
// afresh and forget the full lists; for another Store, use another
// Allocator. Its methods are safe for concurrent use, so long as its
// fields aren't changed meanwhile. Don't copy an Allocator once used.
type Allocator struct {
	// Lists are the lists indices are handed out of, in order: a list
	// is used until FillLimit of it is reserved, then the next. At
	// least one is REQUIRED, and each URI may appear once.
	Lists []AllocatorList

	// Store records the reservations and statuses. REQUIRED.
	Store IndexStore

	// Bits is how many bits each status takes in every list, as in
	// Publisher.Bits; zero means Bits1. SetStatus refuses a status
	// that doesn't fit: StatusSuspended needs Bits2.
	Bits Bits

	// Rand is where random indices are drawn from; nil means
	// crypto/rand.Reader. Set it only in tests: an index an observer
	// can predict is no better than a sequential one.
	Rand io.Reader

	// FillLimit is the share of a list's indices, above zero and at
	// most MaxFillLimit, reserved before Allocate moves on to the next
	// list; zero means DefaultFillLimit.
	FillLimit float64

	mu      sync.Mutex
	checked *allocatorCheck // the settings validate last accepted
}

// allocatorCheck is a copy of the settings of an Allocator that
// validate accepted, and how many of its lists, from the first,
// Allocate has found full.
type allocatorCheck struct {
	lists     []AllocatorList
	bits      Bits
	fillLimit float64
	full      int // guarded by the Allocator's mu
}

// Allocate reserves a random, never-before-allocated index in the
// first list with room, and returns the reference a Referenced Token
// names it by. It returns an error wrapping ErrListsFull when every
// list has reached FillLimit.
func (a *Allocator) Allocate(ctx context.Context) (StatusListRef, error) {
	c, err := a.check()
	if err != nil {
		return StatusListRef{}, err
	}
	exhausted := false
	for i := a.fullLists(c); i < len(c.lists); i++ {
		list := c.lists[i]
		reserved, err := a.Store.Reserved(ctx, list.URI)
		if err != nil {
			return StatusListRef{}, fmt.Errorf("statuslist: counting the reserved indices of %s: %w", list.URI, err)
		}
		if reserved >= a.limit(list) {
			if !exhausted {
				a.filled(c, i)
			}
			continue
		}
		ref, ok, err := a.reserveIn(ctx, list)
		if err != nil {
			return StatusListRef{}, err
		}
		if ok {
			return ref, nil
		}
		exhausted = true
	}
	if exhausted {
		return StatusListRef{}, fmt.Errorf("statuslist: no free index found in %d random draws per list: is Allocator.Rand random?", maxAllocateAttempts)
	}
	return StatusListRef{}, ErrListsFull
}

// MaxAllocateN is the most indices one AllocateN call hands out.
const MaxAllocateN = 1024

// allocateChunk is the most indices AllocateN reserves in a list on one
// count of its reserved indices: concurrent calls each count the list
// before they reserve, so together they can pass its FillLimit by up
// to this much each, as concurrent Allocates pass it by one each.
const allocateChunk = 64

// AllocateN reserves n random, never-before-allocated indices, as n
// Allocate calls would, and returns their references: one for each
// Credential of a batch. It counts a list's reserved indices once per
// 64 indices rather than once per index, takes from each list no more
// than its FillLimit leaves, the rest from the next, and, when Store
// is a BatchIndexStore, reserves each 64 with one ReserveEach, drawing
// again for any index already taken. Concurrent calls can each take a
// list past its FillLimit by up to 64, as concurrent Allocates can by
// one each: size FillLimit's margin below a full list for that. n is
// from 1 to MaxAllocateN. On an error, including one wrapping ErrListsFull
// when every list has reached FillLimit, the indices it reserved stay
// reserved, unused, as an issuance that fails after Allocate leaves
// its index.
func (a *Allocator) AllocateN(ctx context.Context, n int) ([]StatusListRef, error) {
	if n < 1 || n > MaxAllocateN {
		return nil, fmt.Errorf("statuslist: AllocateN of %d indices, not from 1 to %d", n, MaxAllocateN)
	}
	c, err := a.check()
	if err != nil {
		return nil, err
	}
	refs := make([]StatusListRef, 0, n)
	exhausted := false
	for i := a.fullLists(c); i < len(c.lists) && len(refs) < n; {
		list := c.lists[i]
		reserved, err := a.Store.Reserved(ctx, list.URI)
		if err != nil {
			return nil, fmt.Errorf("statuslist: counting the reserved indices of %s: %w", list.URI, err)
		}
		room := a.limit(list) - reserved
		if room <= 0 {
			if !exhausted {
				a.filled(c, i)
			}
			i++
			continue
		}
		want := min(n-len(refs), room, allocateChunk)
		got, err := a.reserveEachIn(ctx, list, want)
		if err != nil {
			return nil, err
		}
		for _, idx := range got {
			refs = append(refs, StatusListRef{Idx: idx, URI: list.URI})
		}
		switch {
		case len(got) < want:
			exhausted = true
			i++
		case want == room:
			i++ // filled to its limit
		}
		// Otherwise the same list again, counted afresh.
	}
	switch {
	case len(refs) == n:
		return refs, nil
	case exhausted:
		return nil, fmt.Errorf("statuslist: no free index found in %d random draws per list: is Allocator.Rand random?", maxAllocateAttempts)
	}
	return nil, ErrListsFull
}

// reserveEachIn reserves up to want random indices of list, drawing
// again for those already reserved, for at most maxAllocateAttempts
// rounds; it returns fewer only if every draw of the last round landed
// on a reserved index.
func (a *Allocator) reserveEachIn(ctx context.Context, list AllocatorList, want int) ([]uint64, error) {
	batch, _ := a.Store.(BatchIndexStore)
	got := make([]uint64, 0, want)
	tried := make(map[uint64]bool, want)
	for range maxAllocateAttempts {
		draw := make([]uint64, 0, want-len(got))
		for len(draw) < want-len(got) {
			idx, err := randomIndex(a.rand(), list.size())
			if err != nil {
				return nil, fmt.Errorf("statuslist: drawing a random index: %w", err)
			}
			if !tried[idx] {
				tried[idx] = true
				draw = append(draw, idx)
			}
			if len(tried) == list.Size {
				break
			}
		}
		if len(draw) == 0 {
			break
		}
		if batch != nil {
			reserved, err := batch.ReserveEach(ctx, list.URI, draw)
			if err != nil {
				return nil, fmt.Errorf("statuslist: reserving indices of %s: %w", list.URI, err)
			}
			asked := make(map[uint64]bool, len(draw))
			for _, idx := range draw {
				asked[idx] = true
			}
			for _, idx := range reserved {
				if !asked[idx] {
					return nil, fmt.Errorf("statuslist: the store reported reserving index %d of %s, which wasn't asked for or was reported twice", idx, list.URI)
				}
				asked[idx] = false
			}
			got = append(got, reserved...)
		} else {
			for _, idx := range draw {
				switch err := a.Store.Reserve(ctx, list.URI, idx); {
				case err == nil:
					got = append(got, idx)
				case !errors.Is(err, ErrIndexTaken):
					return nil, fmt.Errorf("statuslist: reserving an index of %s: %w", list.URI, err)
				}
			}
		}
		if len(got) == want {
			break
		}
	}
	return got, nil
}

// fullLists is how many of c's lists, from the first, are known to be
// full.
func (a *Allocator) fullLists(c *allocatorCheck) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return c.full
}

// filled records that list i of c is full, as are those before it.
func (a *Allocator) filled(c *allocatorCheck, i int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	c.full = max(c.full, i+1)
}

// reserveIn draws random indices in list until one reserves, reporting
// false if every draw lands on a reserved one.
func (a *Allocator) reserveIn(ctx context.Context, list AllocatorList) (StatusListRef, bool, error) {
	for range maxAllocateAttempts {
		idx, err := randomIndex(a.rand(), list.size())
		if err != nil {
			return StatusListRef{}, false, fmt.Errorf("statuslist: drawing a random index: %w", err)
		}
		switch err := a.Store.Reserve(ctx, list.URI, idx); {
		case err == nil:
			return StatusListRef{Idx: idx, URI: list.URI}, true, nil
		case !errors.Is(err, ErrIndexTaken):
			return StatusListRef{}, false, fmt.Errorf("statuslist: reserving an index of %s: %w", list.URI, err)
		}
	}
	return StatusListRef{}, false, nil
}

// SetStatus sets the status of the Referenced Token at ref. It refuses
// a ref naming a list not in Lists, an index outside the list, an index
// Allocate hasn't handed out (wrapping ErrIndexNotReserved), and a
// status that doesn't fit in Bits. Call the list's Publisher's
// Invalidate afterwards, so the change is served at once.
func (a *Allocator) SetStatus(ctx context.Context, ref StatusListRef, status StatusType) error {
	if _, err := a.listFor(ref); err != nil {
		return err
	}
	if uint8(status) > a.bits().mask() {
		return fmt.Errorf("statuslist: status %v doesn't fit in %d bits (Allocator.Bits)", status, a.bits())
	}
	if err := a.Store.SetStatus(ctx, ref.URI, ref.Idx, status); err != nil {
		return fmt.Errorf("statuslist: setting the status of index %d of %s: %w", ref.Idx, ref.URI, err)
	}
	return nil
}

// Status returns the status of the Referenced Token at ref, refusing
// the refs SetStatus refuses. With an error, it returns StatusInvalid,
// as Check does, not the zero value StatusValid.
func (a *Allocator) Status(ctx context.Context, ref StatusListRef) (StatusType, error) {
	if _, err := a.listFor(ref); err != nil {
		return StatusInvalid, err
	}
	status, err := a.Store.Status(ctx, ref.URI, ref.Idx)
	if err != nil {
		return StatusInvalid, fmt.Errorf("statuslist: reading the status of index %d of %s: %w", ref.Idx, ref.URI, err)
	}
	return status, nil
}

// Statuses returns a Publisher.Statuses function for the list at uri,
// read from Store: every index's status, StatusValid at every index
// not handed out. The function fails if uri isn't one of Lists.
func (a *Allocator) Statuses(uri string) func(ctx context.Context) ([]uint8, error) {
	return func(ctx context.Context) ([]uint8, error) {
		list, err := a.listFor(StatusListRef{URI: uri})
		if err != nil {
			return nil, err
		}
		statuses, err := a.Store.Statuses(ctx, uri, list.Size)
		if err != nil {
			return nil, fmt.Errorf("statuslist: reading the statuses of %s: %w", uri, err)
		}
		if len(statuses) != list.Size {
			return nil, fmt.Errorf("statuslist: the store returned %d statuses for %s, not its %d", len(statuses), uri, list.Size)
		}
		return statuses, nil
	}
}

// ListFill is how full one of an Allocator's lists is.
type ListFill struct {
	// URI and Size are the list's, as in Allocator.Lists.
	URI  string
	Size int

	// Limit is how many of its indices are handed out before Allocate
	// moves on to the next list: FillLimit of Size.
	Limit int

	// Reserved is how many of its indices are reserved, as Store
	// counts them. Concurrent AllocateN calls can take it past Limit
	// by up to 64 each.
	Reserved int
}

// Full reports whether Allocate hands out no more indices of the list.
func (f ListFill) Full() bool { return f.Reserved >= f.Limit }

// Free is how many more indices Allocate hands out of the list: zero
// once it's full.
func (f ListFill) Free() int { return max(f.Limit-f.Reserved, 0) }

// Fill reports how full each of Lists is, in order, counting each
// one's reserved indices in Store: Allocate fails with ErrListsFull
// once every one is Full. Watch the Free indices of the lists after
// the last full one, and append a list to Lists before they run out.
// It counts every list each time it's called, so call it from
// monitoring, not on each issuance.
func (a *Allocator) Fill(ctx context.Context) ([]ListFill, error) {
	c, err := a.check()
	if err != nil {
		return nil, err
	}
	fill := make([]ListFill, len(c.lists))
	for i, list := range c.lists {
		reserved, err := a.Store.Reserved(ctx, list.URI)
		if err != nil {
			return nil, fmt.Errorf("statuslist: counting the reserved indices of %s: %w", list.URI, err)
		}
		fill[i] = ListFill{URI: list.URI, Size: list.Size, Limit: a.limit(list), Reserved: reserved}
	}
	return fill, nil
}

// listFor validates a and returns the list ref names, refusing an
// index outside it.
func (a *Allocator) listFor(ref StatusListRef) (AllocatorList, error) {
	c, err := a.check()
	if err != nil {
		return AllocatorList{}, err
	}
	for _, list := range c.lists {
		if list.URI != ref.URI {
			continue
		}
		if ref.Idx >= list.size() {
			return AllocatorList{}, fmt.Errorf("statuslist: index %d is outside %s, which has %d", ref.Idx, ref.URI, list.Size)
		}
		return list, nil
	}
	return AllocatorList{}, fmt.Errorf("statuslist: %q isn't one of Allocator.Lists", ref.URI)
}

// check validates a's settings, unless they're those it last accepted,
// and returns them as accepted.
func (a *Allocator) check() (*allocatorCheck, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c := a.checked; c != nil && a.Store != nil && a.Bits == c.bits && a.FillLimit == c.fillLimit && slices.Equal(a.Lists, c.lists) {
		return c, nil
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	a.checked = &allocatorCheck{lists: slices.Clone(a.Lists), bits: a.Bits, fillLimit: a.FillLimit}
	return a.checked, nil
}

// validate checks a's settings.
func (a *Allocator) validate() error {
	if a.Store == nil {
		return errors.New("statuslist: Allocator.Store is required")
	}
	if len(a.Lists) == 0 {
		return errors.New("statuslist: Allocator.Lists needs at least one list")
	}
	if a.Bits != 0 && !a.Bits.valid() {
		return fmt.Errorf("statuslist: Allocator.Bits is %d, not 1, 2, 4 or 8", a.Bits)
	}
	if math.IsNaN(a.FillLimit) || a.FillLimit < 0 || a.FillLimit > MaxFillLimit {
		return fmt.Errorf("statuslist: Allocator.FillLimit is %v, not above zero and at most %v", a.FillLimit, MaxFillLimit)
	}
	seen := make(map[string]bool, len(a.Lists))
	for i, list := range a.Lists {
		if err := a.validateList(list); err != nil {
			return fmt.Errorf("statuslist: Allocator.Lists[%d]: %w", i, err)
		}
		if seen[list.URI] {
			return fmt.Errorf("statuslist: Allocator.Lists[%d]: %s appears more than once", i, list.URI)
		}
		seen[list.URI] = true
	}
	return nil
}

func (a *Allocator) validateList(list AllocatorList) error {
	u, err := url.Parse(list.URI)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("its URI %q isn't an absolute https URI without userinfo or fragment", list.URI)
	}
	perByte := a.bits().perByte()
	switch {
	case list.Size <= 0:
		return fmt.Errorf("its Size is %d, not positive", list.Size)
	case list.Size%perByte != 0:
		return fmt.Errorf("its Size %d at %d bits per status isn't a whole number of bytes (draft-14 §13.4)", list.Size, a.bits())
	case list.Size/perByte > maxListBytes:
		return fmt.Errorf("its Size %d at %d bits per status packs to over the %d bytes a Checker reads", list.Size, a.bits(), maxListBytes)
	case a.limit(list) < 1:
		return fmt.Errorf("its Size %d at FillLimit %v allows no index", list.Size, a.fillLimit())
	}
	return nil
}

// size is l.Size as an index bound; validate has checked it's positive.
func (l AllocatorList) size() uint64 {
	return uint64(l.Size) // #nosec G115 -- validate refuses a Size that isn't positive
}

// limit is how many of list's indices Allocate hands out.
func (a *Allocator) limit(list AllocatorList) int {
	return int(a.fillLimit() * float64(list.Size))
}

func (a *Allocator) fillLimit() float64 {
	if a.FillLimit == 0 {
		return DefaultFillLimit
	}
	return a.FillLimit
}

func (a *Allocator) bits() Bits {
	if a.Bits == 0 {
		return Bits1
	}
	return a.Bits
}

func (a *Allocator) rand() io.Reader {
	if a.Rand == nil {
		return rand.Reader
	}
	return a.Rand
}

// randomIndex returns an index uniformly distributed in [0, size),
// size > 0: it draws 64 random bits, keeps as many as size-1 needs,
// and draws again when the result is size or more, so no index is
// likelier than another, as a modulo would make the low ones.
func randomIndex(r io.Reader, size uint64) (uint64, error) {
	mask := uint64(math.MaxUint64)
	if n := bits.Len64(size - 1); n < 64 {
		mask = 1<<n - 1
	}
	var buf [8]byte
	for {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		if idx := binary.BigEndian.Uint64(buf[:]) & mask; idx < size {
			return idx, nil
		}
	}
}
