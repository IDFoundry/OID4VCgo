package walletprovider

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
)

// statusLists is a Provider's state for its status lists: the handler
// serving them, the Publishers of the lists served lately, and where
// the current period's lists have filled up to.
type statusLists struct {
	handler *http.ServeMux

	mu         sync.Mutex
	publishers map[string]servedList // by list URI
	fillStart  int64                 // the period fillFrom is for
	fillFrom   int                   // the first of its lists not known to be full
}

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
// starting at start, from list from on, in order: the default fill
// limit fills each before the next.
func (p *Provider) allocator(start int64, from int) *statuslist.Allocator {
	lists := make([]statuslist.AllocatorList, 0, MaxStatusListsPerPeriod-from)
	for n := from; n < MaxStatusListsPerPeriod; n++ {
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

// allocateStatus reserves an index on a list of the period now is in.
func (p *Provider) allocateStatus(ctx context.Context, now time.Time) (statuslist.StatusListRef, error) {
	start := p.periodStart(now)
	ref, err := p.allocator(start, p.lists.firstWithRoom(start)).Allocate(ctx)
	switch {
	case errors.Is(err, statuslist.ErrListsFull):
		return statuslist.StatusListRef{}, fmt.Errorf("walletprovider: the status lists of the current period are full: raise Config.StatusListSize or shorten Config.StatusListPeriod: %w", err)
	case err != nil:
		return statuslist.StatusListRef{}, fmt.Errorf("walletprovider: allocating a status index: %w", err)
	}
	if _, n, ok := p.parseList(ref.URI); ok {
		p.lists.filledBefore(start, n)
	}
	return ref, nil
}

// firstWithRoom is the first list of the period starting at start that
// isn't known to be full, so Allocate needn't count the reserved
// indices of every list before it.
func (l *statusLists) firstWithRoom(start int64) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if start != l.fillStart {
		return 0
	}
	return l.fillFrom
}

// filledBefore records that an index was reserved on list n of the
// period starting at start: Allocate moves to a list only once those
// before it are full, and a full list stays full.
func (l *statusLists) filledBefore(start int64, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if start > l.fillStart {
		l.fillStart, l.fillFrom = start, 0
	}
	if start == l.fillStart {
		l.fillFrom = max(l.fillFrom, n)
	}
}

// inCurrentPeriod returns ik with its Status on a list of now's period,
// moving it there first if it's on an earlier period's list or on no
// period's (a record from before lists had periods): a fresh index, the
// old Status kept as PreviousStatus while an attestation naming it may
// be live, that is, if it's the previous period's, and a RetainUntil
// from the current period's start. The record changes
// with a compare-and-swap (InstanceKeyStore.Update); should another
// request have moved it meanwhile, its move stands, and the index
// reserved here stays reserved, as every allocated index does.
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
	ref, err := p.allocateStatus(ctx, now)
	if err != nil {
		return InstanceKey{}, err
	}
	for range maxUpdateAttempts {
		moved := ik
		moved.Status, moved.PreviousStatus, moved.RetainUntil = ref, statuslist.StatusListRef{}, p.retainUntil(cur)
		if start, _, ok := p.parseList(ik.Status.URI); ok && start == cur-p.period() {
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

// setStatus sets the status at ref, if its list is served: no live
// attestation names another.
func (p *Provider) setStatus(ctx context.Context, ref statuslist.StatusListRef, status statuslist.StatusType, now time.Time) error {
	start, _, ok := p.parseList(ref.URI)
	if !ok || !p.served(start, now) {
		return nil
	}
	if err := p.allocator(start, 0).SetStatus(ctx, ref, status); err != nil {
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
// stops after maxEmptyPeriods periods in a row with no list: a
// period's lists fill one after another, so one whose first list has
// no index reserved has none. Run it periodically — daily, say — from
// one process, as sqlstore's DB.Sweep is run; it's safe to run from
// several at once, or again after a failure, which leaves what it
// didn't delete for the next run.
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
// have an index reserved, and returns how many it deleted. It deletes
// the last first, so should one fail, those before it, list 0 among
// them, are still found next time.
func (p *Provider) deleteLists(ctx context.Context, start int64) (int, error) {
	n := 0
	for ; n < MaxStatusListsPerPeriod; n++ {
		uri := p.listURI(start, n)
		reserved, err := p.deps.StatusIndices.Reserved(ctx, uri)
		if err != nil {
			return 0, fmt.Errorf("walletprovider: counting the reserved indices of %s: %w", uri, err)
		}
		if reserved == 0 {
			break
		}
	}
	for i := n - 1; i >= 0; i-- {
		uri := p.listURI(start, i)
		if err := p.deps.StatusIndices.Delete(ctx, uri); err != nil {
			return n - 1 - i, fmt.Errorf("walletprovider: deleting the status list %s: %w", uri, err)
		}
	}
	return n, nil
}

// StatusLists serves the provider's status lists: an http.Handler to
// mount at Config.StatusListBaseURI, answering GET /{start}/{n} with
// the list at StatusListBaseURI/{start}/{n}, in the JWT form
// (application/statuslist+jwt) by default and the CWT form when the
// request's Accept header asks for it (draft-ietf-oauth-status-list-14
// §8.1), signed with Signer and carrying Chain. Each instance key's
// status is two bits: VALID, INVALID (revoked) or SUSPENDED. It serves
// the lists of the periods an attestation may name, from two periods
// before the current one to the next, that have an index handed out,
// and answers 404 for any other. The provider invalidates a list's
// cached token whenever it changes a status on it.
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
	reserved, err := p.deps.StatusIndices.Reserved(ctx, uri)
	switch {
	case err != nil:
		return nil, false, fmt.Errorf("walletprovider: counting the reserved indices of %s: %w", uri, err)
	case reserved == 0:
		return nil, false, nil
	}
	return p.lists.add(uri, servedList{start: start, pub: &statuslist.Publisher{
		URI: uri, Signer: p.deps.Signer, Chain: p.deps.Chain,
		Statuses: p.allocator(start, 0).Statuses(uri), Bits: statuslist.Bits2,
		Lifetime: p.cfg.StatusListLifetime, TTL: p.cfg.StatusListTTL, Now: p.now,
		Tokens: p.deps.StatusListTokens,
	}}, func(start int64) bool { return p.served(start, now) }), true, nil
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
