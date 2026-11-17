package walletprovider

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// statusLists is a Provider's state for its status lists: the handler
// serving them, the Publishers of the lists served lately, and where
// which of the current period's lists are known to be full.
type statusLists struct {
	handler *http.ServeMux

	mu         sync.Mutex
	publishers map[string]servedList // by list URI
	empty      map[string]time.Time  // lists found with no index reserved, by URI, until when that's believed
	fillStart  int64                 // the period full is for
	full       uint64                // its lists known to be full: bit n for list n
}

// emptyListTTL is how long the handler answers 404 for a list it found
// no index reserved on without counting again: requests for lists that
// aren't in use then cost one count a second each, not one each. It's
// short, as another process may reserve the list's first index
// meanwhile, and an attestation naming it then has its list answer 404
// here for at most that long; this process's own reservations end it
// at once.
const emptyListTTL = time.Second

// servedList is a served list's Publisher and its period's start.
type servedList struct {
	start int64
	pub   *statuslist.Publisher
}

// period is Config.StatusListPeriod in seconds.
func (p *Provider) period() int64 { return int64(p.cfg.StatusListPeriod / time.Second) }

// periodStart is the start of the period t is in, in seconds since the
// Unix epoch.
func (p *Provider) periodStart(t time.Time) int64 {
	s, period := t.Unix(), p.period()
	return s - (s%period+period)%period
}

// retainUntil is the RetainUntil of an instance key on the lists of
// the period starting at start.
func (p *Provider) retainUntil(start int64) time.Time {
	return time.Unix(start, 0).Add(p.cfg.InstanceKeyRetention)
}

// listURI is the uri of list n of the period starting at start.
func (p *Provider) listURI(start int64, n int) string {
	return p.cfg.StatusListBaseURI + "/" + strconv.FormatInt(start, 10) + "/" + strconv.Itoa(n)
}

// allocator is a statuslist.Allocator over the lists of the period
// starting at start, from list from up to list to, in order: the
// default fill limit fills each before the next.
func (p *Provider) allocator(start int64, from, to int) *statuslist.Allocator {
	lists := make([]statuslist.AllocatorList, 0, to-from)
	for n := from; n < to; n++ {
		lists = append(lists, statuslist.AllocatorList{URI: p.listURI(start, n), Size: p.cfg.StatusListSize})
	}
	return &statuslist.Allocator{Lists: lists, Store: p.deps.StatusIndices, Bits: statuslist.Bits2}
}

// parseList returns the period start and number of the list at uri,
// reporting false for a uri that isn't a period's list as listURI
// writes it: one from before lists had periods, or of another
// StatusListPeriod.
func (p *Provider) parseList(uri string) (int64, int, bool) {
	rest, ok := strings.CutPrefix(uri, p.cfg.StatusListBaseURI+"/")
	if !ok {
		return 0, 0, false
	}
	startText, nText, _ := strings.Cut(rest, "/")
	return p.list(startText, nText)
}

// list parses a list's period start and number, as listURI writes
// them: decimal, without sign or leading zeros, the start a multiple
// of the period and the number below MaxStatusListsPerPeriod.
func (p *Provider) list(startText, nText string) (int64, int, bool) {
	start, err := strconv.ParseInt(startText, 10, 64)
	if err != nil || start%p.period() != 0 || strconv.FormatInt(start, 10) != startText {
		return 0, 0, false
	}
	n, err := strconv.Atoi(nText)
	if err != nil || n < 0 || n >= MaxStatusListsPerPeriod || strconv.Itoa(n) != nText {
		return 0, 0, false
	}
	return start, n, true
}

// served reports whether the lists of the period starting at start are
// served at now. A live attestation names the current period's list or
// the previous one's, since it outlives its period by less than
// another; one period more each way allows for the clocks of the
// processes serving the provider to disagree.
func (p *Provider) served(start int64, now time.Time) bool {
	cur := p.periodStart(now)
	return start >= cur-2*p.period() && start <= cur+p.period()
}

// allocateStatus reserves an index on a list of the period now is in
// for an instance key of the instance id, first counting it against the
// instance's Config.MaxInstanceKeysPerPeriod (countIndex): on the
// period's first Config.RecentInstanceStatusLists lists for an
// instance registered in the period or the one before, and on any
// list for any other (allocate).
func (p *Provider) allocateStatus(ctx context.Context, id string, now time.Time) (statuslist.StatusListRef, error) {
	start := p.periodStart(now)
	recent, err := p.countIndex(ctx, id, start)
	if err != nil {
		return statuslist.StatusListRef{}, err
	}
	ref, err := p.allocate(ctx, start, recent)
	switch {
	case errors.Is(err, statuslist.ErrListsFull) && recent && p.cfg.RecentInstanceStatusLists < MaxStatusListsPerPeriod:
		p.uncountIndex(ctx, id, start)
		p.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn,
			"walletprovider: the status lists of the current period that recently registered instances take indices from are full",
			slog.String("instance", id))
		return statuslist.StatusListRef{}, fmt.Errorf("walletprovider: the status lists of the current period that instances registered in it or the one before take indices from are full (Config.RecentInstanceStatusLists): raise Config.StatusListSize, and look into the recent registrations: %w", err)
	case errors.Is(err, statuslist.ErrListsFull):
		p.uncountIndex(ctx, id, start)
		return statuslist.StatusListRef{}, fmt.Errorf("walletprovider: the status lists of the current period are full: raise Config.StatusListSize or shorten Config.StatusListPeriod: %w", err)
	case err != nil:
		return statuslist.StatusListRef{}, fmt.Errorf("walletprovider: allocating a status index: %w", err)
	}
	p.lists.reserved(ref.URI)
	return ref, nil
}

// allocate reserves an index on a list of the period starting at
// start. A recent instance's key takes one on the period's first
// Config.RecentInstanceStatusLists lists only, so recent instances
// can't take the room the others need. Another's takes one on any
// list: on the recent instances' share, chosen at random in proportion
// to its size, while that share is no fuller than the other lists
// (shareNoFuller), and otherwise on the other lists, the share only
// once they're full. The recent instances' lists then hold the others'
// keys about as densely as the rest do while recent instances are few, so a
// list's number tells little about whether an instance registered
// recently; established instances' keys don't take room on the share
// the recent instances' own keys need while the other lists have it;
// and a burst of recent instances filling their share leaves the
// others the rest.
func (p *Provider) allocate(ctx context.Context, start int64, recent bool) (statuslist.StatusListRef, error) {
	split := p.cfg.RecentInstanceStatusLists
	if recent || split >= MaxStatusListsPerPeriod {
		return p.allocateIn(ctx, start, 0, split)
	}
	inShare := false
	if p.lists.shareNoFuller(start, split) {
		var err error
		if inShare, err = p.pickRecentShare(split); err != nil {
			return statuslist.StatusListRef{}, err
		}
	}
	first, second := [2]int{split, MaxStatusListsPerPeriod}, [2]int{0, split}
	if inShare {
		first, second = second, first
	}
	ref, err := p.allocateIn(ctx, start, first[0], first[1])
	if !errors.Is(err, statuslist.ErrListsFull) {
		return ref, err
	}
	return p.allocateIn(ctx, start, second[0], second[1])
}

// pickRecentShare reports, at random with probability
// split/MaxStatusListsPerPeriod, whether an established instance's key
// is to take its index on the recent instances' share of the lists.
func (p *Provider) pickRecentShare(split int) (bool, error) {
	if split <= 0 {
		return false, nil
	}
	var b [2]byte
	if _, err := io.ReadFull(p.deps.Random, b[:]); err != nil {
		return false, fmt.Errorf("walletprovider: choosing a status list: %w", err)
	}
	// 2^16 is a multiple of MaxStatusListsPerPeriod: no bias.
	return int(binary.BigEndian.Uint16(b[:]))%MaxStatusListsPerPeriod < split, nil
}

// allocateIn reserves an index on the first list with room of lists
// from up to to of the period starting at start.
func (p *Provider) allocateIn(ctx context.Context, start int64, from, to int) (statuslist.StatusListRef, error) {
	first := p.lists.firstWithRoom(start, from, to)
	if first >= to {
		return statuslist.StatusListRef{}, statuslist.ErrListsFull
	}
	ref, err := p.allocator(start, first, to).Allocate(ctx)
	if errors.Is(err, statuslist.ErrListsFull) {
		// Recorded, so the next request needn't count them again.
		p.lists.filledBefore(start, from, to)
	}
	if err != nil {
		return statuslist.StatusListRef{}, err
	}
	if _, n, ok := p.parseList(ref.URI); ok {
		p.lists.filledBefore(start, from, n)
	}
	return ref, nil
}

// recent reports whether in was registered in the period starting at
// start or the one before (Config.RecentInstanceStatusLists).
func (p *Provider) recent(in Instance, start int64) bool {
	return !in.CreatedAt.IsZero() && p.periodStart(in.CreatedAt) >= start-p.period()
}

// countIndex counts one more status list index taken by the instance
// id's instance keys in the period starting at start, refusing it with
// ErrTooManyInstanceKeys once they've taken
// Config.MaxInstanceKeysPerPeriod, and refusing an instance that isn't
// active. It's counted before the index is reserved, so concurrent
// requests can't take more between them; an index then not recorded,
// or not reserved for another reason than the lists being full
// (uncountIndex), stays counted. A period earlier than the one the
// instance counts in, from a process whose clock is behind, counts in
// the later one. It reports whether the instance is recent (recent).
func (p *Provider) countIndex(ctx context.Context, id string, start int64) (bool, error) {
	recent := false
	err := p.update(ctx, id, func(cur *Instance) error {
		recent = p.recent(*cur, start)
		if err := stateError(cur.State); err != nil {
			return err
		}
		if start > cur.IndexPeriodStart {
			cur.IndexPeriodStart, cur.IndicesInPeriod = start, 0
		}
		if cur.IndicesInPeriod >= p.cfg.MaxInstanceKeysPerPeriod {
			return fmt.Errorf("%w: the instance's keys took %d status list indices this period", ErrTooManyInstanceKeys, cur.IndicesInPeriod)
		}
		cur.IndicesInPeriod++
		return nil
	})
	return recent, err
}

// uncountIndex gives back the count countIndex took in the period
// starting at start for an index the period's full lists didn't hand
// out, so neither a renewal that keeps its previous period's index nor
// a refused new key uses up the instance's quota. Should that fail,
// the instance is one count short this period, which is logged.
func (p *Provider) uncountIndex(ctx context.Context, id string, start int64) {
	ctx = context.WithoutCancel(ctx)
	err := p.update(ctx, id, func(cur *Instance) error {
		if cur.IndexPeriodStart == start && cur.IndicesInPeriod > 0 {
			cur.IndicesInPeriod--
		}
		return nil
	})
	if err != nil {
		p.logger().LogAttrs(ctx, slog.LevelWarn, "walletprovider: giving back a status list index the full lists didn't hand out",
			slog.String("instance", id), slog.Any("error", err))
	}
}

// StatusListFill is how full the status lists of a period are.
type StatusListFill struct {
	// Start and End are when the period starts and ends.
	Start, End time.Time

	// Lists are its MaxStatusListsPerPeriod lists, in order. The keys of
	// instances registered in the period or the one before take indices
	// from the first RecentInstanceLists of them, one after another;
	// other instances' keys from the rest, one after another, and from
	// those first ones too, at random, while they're no fuller than the
	// rest, or once the rest are full.
	Lists []statuslist.ListFill

	// RecentInstanceLists is Config.RecentInstanceStatusLists.
	RecentInstanceLists int
}

// Free is how many more instance keys the period's lists take: an
// attestation for one more fails until End.
func (f StatusListFill) Free() int {
	free := 0
	for _, list := range f.Lists {
		free += list.Free()
	}
	return free
}

// RecentInstanceFree is how many more instance keys of instances
// registered in the period or the one before the period's lists take:
// an attestation for one more such key fails until End. Once it's zero
// with Free well above it, recently registered instances, many of them,
// have filled their share.
func (f StatusListFill) RecentInstanceFree() int {
	free := 0
	for _, list := range f.Lists[:min(f.RecentInstanceLists, len(f.Lists))] {
		free += list.Free()
	}
	return free
}

// StatusListFill reports how full the current period's status lists
// are: they take every instance key first used, or used again, in the
// period, and once they're full, a Wallet or Key Attestation for one
// more fails until the next period, unless it's for a recorded key last
// used in the previous period, which keeps that period's index; for a
// recently registered instance's key, once the lists of its share are
// full (RecentInstanceFree). Compare Free with the instance keys the
// rest of the period will use; if they won't fit, raise
// Config.StatusListSize, which the current period's lists take too. It counts
// the reserved indices of every list of the period, so call it from
// monitoring, not on each request.
func (p *Provider) StatusListFill(ctx context.Context) (StatusListFill, error) {
	start := p.periodStart(p.now())
	lists, err := p.allocator(start, 0, MaxStatusListsPerPeriod).Fill(ctx)
	if err != nil {
		return StatusListFill{}, fmt.Errorf("walletprovider: reading how full the status lists are: %w", err)
	}
	return StatusListFill{
		Start: time.Unix(start, 0), End: time.Unix(start+p.period(), 0),
		Lists: lists, RecentInstanceLists: p.cfg.RecentInstanceStatusLists,
	}, nil
}

// firstWithRoom is the first of lists from up to to of the period
// starting at start that isn't known to be full, or to if none is, so
// Allocate needn't count the reserved indices of every list before it.
func (l *statusLists) firstWithRoom(start int64, from, to int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := from
	if start == l.fillStart {
		for n < to && l.full&(1<<n) != 0 {
			n++
		}
	}
	return n
}

// shareNoFuller reports whether the recent instances' share, the first
// split lists of the period starting at start, is no fuller than the
// other lists: no larger a part of it is known to be full. It's
// judged by the lists this process has found full, so with several
// processes it's approximate: a list another process filled counts
// here once this one finds it full, the next time it takes an index on
// those lists. A process that last took one on the share before others
// filled more of it may put one established instance's key there that
// the share's fill wouldn't have let it, and then knows better. It
// never refuses a recent instance's key: Allocate counts the share's
// room for that.
func (l *statusLists) shareNoFuller(start int64, split int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if start != l.fillStart {
		return true
	}
	share := uint64(1)<<split - 1
	inShare, rest := bits.OnesCount64(l.full&share), bits.OnesCount64(l.full&^share)
	return inShare*(MaxStatusListsPerPeriod-split) <= rest*split
}

// filledBefore records that lists from up to n of the period starting
// at start are full: an Allocate over lists from on reserved an index
// on list n, which it moves to only once those before it are full, or
// found every list up to n full. A full list stays full.
func (l *statusLists) filledBefore(start int64, from, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if start > l.fillStart {
		l.fillStart, l.full = start, 0
	}
	if start == l.fillStart {
		for i := from; i < n; i++ {
			l.full |= 1 << i
		}
	}
}

// inCurrentPeriod returns ik with its Status on a list of now's period,
// moving it there first if it's on an earlier period's list or on no
// period's (a record from before lists had periods): a fresh index, the
// old Status kept as PreviousStatus while an attestation naming it may
// be live, that is, while its list is served, and a RetainUntil from
// the current period's start. Should the current period's lists be
// full, a key on the previous period's list keeps its index there,
// unmoved, even once the instance has used up its quota, which keeping
// it takes none of: that list is served until every attestation naming
// it has expired, so the key's renewal doesn't fail with the lists, as
// a new key's attestation does. Its status is set as long as the record names
// the index: as Status while the key stays, and as PreviousStatus once
// it moves, its list still served then, so a revocation still reaches
// the attestations issued late in the full period. A key that moves
// only once that list is no longer served has no live attestation
// naming the index. The record changes with a compare-and-swap
// (InstanceKeyStore.Update); should another request have moved it
// meanwhile, its move stands, and the index reserved here stays
// reserved, as every allocated index does.
//
// A move happens before recordUse, which refuses an instance that
// isn't active, and Suspend and Revoke store the state before they
// list the instance's keys: either they find the moved record and set
// both its statuses, or this request sees the new state and gets
// nothing, and the new index, VALID, is named by no attestation while
// the instance isn't active.
func (p *Provider) inCurrentPeriod(ctx context.Context, ik InstanceKey, now time.Time) (InstanceKey, error) {
	cur := p.periodStart(now)
	current := func(ref statuslist.StatusListRef) bool {
		start, _, ok := p.parseList(ref.URI)
		return ok && start >= cur && p.served(start, now)
	}
	if current(ik.Status) {
		return ik, nil
	}
	ref, err := p.allocateStatus(ctx, ik.InstanceID, now)
	if errors.Is(err, ErrTooManyInstanceKeys) && p.onPreviousPeriod(ik.Status, cur) {
		// The quota is counted before the lists are found full, but
		// keeping the previous period's index takes none of it.
		err = p.quotaOrListsFull(ctx, ik.InstanceID, cur, err)
	}
	switch {
	case errors.Is(err, statuslist.ErrListsFull) && p.onPreviousPeriod(ik.Status, cur):
		p.logger().LogAttrs(context.WithoutCancel(ctx), slog.LevelWarn,
			"walletprovider: the current period's status lists are full: a recorded instance key keeps its previous period's index",
			slog.String("instance", ik.InstanceID), slog.String("list", ik.Status.URI))
		return ik, nil
	case err != nil:
		return InstanceKey{}, err
	}
	for range maxUpdateAttempts {
		moved := ik
		moved.Status, moved.PreviousStatus, moved.RetainUntil = ref, statuslist.StatusListRef{}, p.retainUntil(cur)
		if start, _, ok := p.parseList(ik.Status.URI); ok && p.served(start, now) {
			moved.PreviousStatus = ik.Status
		}
		// A record swept meanwhile (InstanceKeyRetention) is refused as
		// a key never recorded is.
		switch err := p.deps.InstanceKeys.Update(ctx, moved); {
		case err == nil:
			moved.Revision++
			return moved, nil
		case errors.Is(err, ErrNotFound):
			return InstanceKey{}, ErrUnknownInstanceKey
		case !errors.Is(err, ErrConflict):
			return InstanceKey{}, fmt.Errorf("walletprovider: moving an instance key to the current status lists: %w", err)
		}
		switch ik, err = p.deps.InstanceKeys.Get(ctx, ik.Thumbprint); {
		case errors.Is(err, ErrNotFound):
			return InstanceKey{}, ErrUnknownInstanceKey
		case err != nil:
			return InstanceKey{}, fmt.Errorf("walletprovider: reading instance key: %w", err)
		}
		if current(ik.Status) {
			return ik, nil
		}
	}
	return InstanceKey{}, fmt.Errorf("walletprovider: moving an instance key to the current status lists: %w after %d attempts", ErrConflict, maxUpdateAttempts)
}

// quotaOrListsFull returns an error wrapping statuslist.ErrListsFull
// if the lists of the period starting at start that the instance id's
// keys take indices from are all full, and quota, the instance's
// ErrTooManyInstanceKeys, if they aren't or that can't be told.
func (p *Provider) quotaOrListsFull(ctx context.Context, id string, start int64, quota error) error {
	in, err := p.getInstance(ctx, id)
	if err != nil {
		return quota
	}
	split := p.cfg.RecentInstanceStatusLists
	full, err := p.listsFull(ctx, start, 0, split)
	if err == nil && full && !p.recent(in, start) && split < MaxStatusListsPerPeriod {
		full, err = p.listsFull(ctx, start, split, MaxStatusListsPerPeriod)
	}
	if err != nil || !full {
		return quota
	}
	return fmt.Errorf("walletprovider: the status lists of the current period are full: %w", statuslist.ErrListsFull)
}

// listsFull reports whether lists from up to to of the period starting
// at start are all full, counting the reserved indices of those not
// known to be full until one has room, and recording those it finds
// full.
func (p *Provider) listsFull(ctx context.Context, start int64, from, to int) (bool, error) {
	for n := p.lists.firstWithRoom(start, from, to); n < to; n++ {
		fill, err := p.allocator(start, n, n+1).Fill(ctx)
		if err != nil {
			return false, err
		}
		if !fill[0].Full() {
			return false, nil
		}
		p.lists.filledBefore(start, from, n+1)
	}
	return true, nil
}

// onPreviousPeriod reports whether ref is on a list of the period
// before the one starting at cur.
func (p *Provider) onPreviousPeriod(ref statuslist.StatusListRef, cur int64) bool {
	start, _, ok := p.parseList(ref.URI)
	return ok && start == cur-p.period()
}

// setStatus sets the status at ref, if its list is served: no live
// attestation names another.
func (p *Provider) setStatus(ctx context.Context, ref statuslist.StatusListRef, status statuslist.StatusType, now time.Time) error {
	start, _, ok := p.parseList(ref.URI)
	if !ok || !p.served(start, now) {
		return nil
	}
	if err := p.allocator(start, 0, MaxStatusListsPerPeriod).SetStatus(ctx, ref, status); err != nil {
		return fmt.Errorf("walletprovider: setting an instance key's status to %v: %w", status, err)
	}
	p.lists.invalidate(ref.URI)
	return nil
}

// maxEmptyPeriods is how many periods in a row without a list
// SweepStatusLists passes before it looks no further back.
const maxEmptyPeriods = 8

// SweepStatusLists deletes the status lists of the periods before those
// StatusLists serves (statuslist.IndexStore.Delete) and returns how many
// it deleted. No live attestation names one of them, and no index is
// handed out of one again; an instance key whose Status or
// PreviousStatus names one gets an index on the current period's lists
// when it's next used, and Suspend, Resume and Revoke pass it by, as
// they do every list no longer served. Without it, every list of every
// period stays in the IndexStore for good.
//
// It walks back from the period before the oldest one served, and
// stops after maxEmptyPeriods periods in a row with no list, counting
// the reserved indices of each of a period's lists. Run it periodically — daily, say — from
// any instance; it's safe to run from several at once, or again after
// a failure, which leaves what it didn't delete for the next run.
//
// First, when the InstanceKeyStore is an UnretainedInstanceKeyLister,
// it gives each instance key with no RetainUntil, one recorded or last
// moved before the provider set one, the RetainUntil it would have
// had: from the start of its Status's period, the one it was last used
// in, since using it in a later one moves it. A key on no period's
// list (the single list of v0.67.0 and before) hasn't been used since
// the upgrade that stopped serving that list, so it gets one from the
// current period's start, keeping it at least as long as it would
// have been kept. The InstanceKeyStore can then delete it once that
// has passed, as it does any other record.
func (p *Provider) SweepStatusLists(ctx context.Context) (int, error) {
	if err := p.retainUnretained(ctx); err != nil {
		return 0, err
	}
	period := p.period()
	deleted, empty := 0, 0
	// The oldest period served starts two periods before the current
	// one (served).
	for start := p.periodStart(p.now()) - 3*period; empty < maxEmptyPeriods; start -= period {
		n, err := p.deleteLists(ctx, start)
		deleted += n
		switch {
		case err != nil:
			return deleted, err
		case n == 0:
			empty++
		default:
			empty = 0
		}
	}
	return deleted, nil
}

// retainUnretained gives each instance key with no RetainUntil one, as
// SweepStatusLists says, with a compare-and-swap: a key moved or
// deleted meanwhile is left as it now is.
func (p *Provider) retainUnretained(ctx context.Context) error {
	lister, ok := p.deps.InstanceKeys.(UnretainedInstanceKeyLister)
	if !ok {
		return nil
	}
	cur := p.periodStart(p.now())
	for after := ""; ; {
		page, err := lister.ListUnretained(ctx, after, listPageSize)
		if err != nil {
			return fmt.Errorf("walletprovider: listing instance keys without a RetainUntil: %w", err)
		}
		for _, ik := range page {
			start, _, onPeriodList := p.parseList(ik.Status.URI)
			if !onPeriodList {
				start = cur
			}
			ik.RetainUntil = p.retainUntil(start)
			if err := p.deps.InstanceKeys.Update(ctx, ik); err != nil && !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("walletprovider: setting an instance key's RetainUntil: %w", err)
			}
		}
		if len(page) < listPageSize {
			return nil
		}
		after = page[len(page)-1].Thumbprint
	}
}

// deleteLists deletes the lists of the period starting at start that
// have an index reserved, and returns how many it deleted. Each of
// them is checked: a period's lists fill one after another within
// each of Config.RecentInstanceStatusLists's two shares, which an
// earlier configuration may have divided elsewhere. Should a Delete
// fail, the lists not deleted still count their indices next time.
func (p *Provider) deleteLists(ctx context.Context, start int64) (int, error) {
	deleted := 0
	for n := range MaxStatusListsPerPeriod {
		uri := p.listURI(start, n)
		reserved, err := p.deps.StatusIndices.Reserved(ctx, uri)
		if err != nil {
			return deleted, fmt.Errorf("walletprovider: counting the reserved indices of %s: %w", uri, err)
		}
		if reserved == 0 {
			continue
		}
		if err := p.deps.StatusIndices.Delete(ctx, uri); err != nil {
			return deleted, fmt.Errorf("walletprovider: deleting the status list %s: %w", uri, err)
		}
		deleted++
	}
	return deleted, nil
}

// StatusLists serves the provider's status lists: an http.Handler to
// mount at Config.StatusListBaseURI, with http.StripPrefix of the base
// URI's path unless that's empty, answering GET /{start}/{n} with
// the list at StatusListBaseURI/{start}/{n}, in the JWT form
// (application/statuslist+jwt) by default and the CWT form when the
// request's Accept header asks for it (draft-ietf-oauth-status-list-14
// §8.1), signed with Signer and carrying Chain. Each instance key's
// status is two bits: VALID, INVALID (revoked) or SUSPENDED. It serves
// the lists of the periods an attestation may name, from two periods
// before the current one to the next, that have an index handed out,
// and answers 404 for any other: for a second without counting its
// indices again, for a list it found with none handed out. The provider
// invalidates a list's cached token whenever it changes a status on it.
func (p *Provider) StatusLists() http.Handler { return p.lists.handler }

func (p *Provider) serveStatusList(w http.ResponseWriter, r *http.Request) {
	pub, ok, err := p.publisher(r.Context(), r.PathValue("start"), r.PathValue("n"))
	switch {
	case err != nil:
		p.logger().LogAttrs(context.WithoutCancel(r.Context()), slog.LevelError, "walletprovider: serving a status list",
			slog.String("path", r.URL.Path), slog.Any("error", err))
		http.Error(w, "the status list is unavailable", http.StatusInternalServerError)
	case !ok:
		http.NotFound(w, r)
	default:
		pub.ServeHTTP(w, r)
	}
}

// publisher returns the Publisher of the list startText and nText name,
// reporting false if it isn't served. A list no index was handed out of
// isn't: serving every such list would have the provider sign lists by
// the thousand for anyone asking.
func (p *Provider) publisher(ctx context.Context, startText, nText string) (*statuslist.Publisher, bool, error) {
	now := p.now()
	start, n, ok := p.list(startText, nText)
	if !ok || !p.served(start, now) {
		return nil, false, nil
	}
	uri := p.listURI(start, n)
	if pub := p.lists.get(uri); pub != nil {
		return pub, true, nil
	}
	if p.lists.knownEmpty(uri, now) {
		return nil, false, nil
	}
	reserved, err := p.deps.StatusIndices.Reserved(ctx, uri)
	switch {
	case err != nil:
		return nil, false, fmt.Errorf("walletprovider: counting the reserved indices of %s: %w", uri, err)
	case reserved == 0:
		p.lists.foundEmpty(uri, now)
		return nil, false, nil
	}
	return p.lists.add(uri, servedList{start: start, pub: &statuslist.Publisher{
		URI: uri, Signer: p.deps.Signer, Chain: p.deps.Chain,
		Statuses: p.allocator(start, 0, MaxStatusListsPerPeriod).Statuses(uri), Bits: statuslist.Bits2,
		Lifetime: p.cfg.StatusListLifetime, TTL: p.cfg.StatusListTTL, Now: p.now,
		Tokens: p.deps.StatusListTokens,
	}}, func(start int64) bool { return p.served(start, now) }), true, nil
}

// knownEmpty reports whether the list at uri was found with no index
// reserved less than emptyListTTL before now.
func (l *statusLists) knownEmpty(uri string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, ok := l.empty[uri]
	return ok && now.Before(until)
}

// foundEmpty records that the list at uri had no index reserved at
// now, dropping the records that have lapsed: the handler serves a
// bounded set of lists, so there are at most that many.
func (l *statusLists) foundEmpty(uri string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for u, until := range l.empty {
		if !now.Before(until) {
			delete(l.empty, u)
		}
	}
	if l.empty == nil {
		l.empty = make(map[string]time.Time)
	}
	l.empty[uri] = now.Add(emptyListTTL)
}

// reserved records that an index was reserved on the list at uri: it's
// no longer empty.
func (l *statusLists) reserved(uri string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.empty, uri)
}

func (l *statusLists) get(uri string) *statuslist.Publisher {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.publishers[uri].pub
}

// add caches s as the Publisher of the list at uri, unless a concurrent
// request cached one first, and returns the one cached. It drops the
// lists whose period served no longer reports.
func (l *statusLists) add(uri string, s servedList, served func(start int64) bool) *statuslist.Publisher {
	l.mu.Lock()
	defer l.mu.Unlock()
	if cached, ok := l.publishers[uri]; ok {
		return cached.pub
	}
	for u, cached := range l.publishers {
		if !served(cached.start) {
			delete(l.publishers, u)
		}
	}
	if l.publishers == nil {
		l.publishers = make(map[string]servedList)
	}
	l.publishers[uri] = s
	return s.pub
}

// invalidate drops the cached tokens of the list at uri, if it's
// served.
func (l *statusLists) invalidate(uri string) {
	l.mu.Lock()
	cached, ok := l.publishers[uri]
	l.mu.Unlock()
	if ok {
		cached.pub.Invalidate()
	}
}
