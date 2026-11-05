// Package statuscache is the engine behind statuslist.Cache, which
// identifierlist's Checker uses too: a bounded cache, keyed by uri and
// media type, of what a caller's verification of a status list token
// found that depends on the token's bytes alone, kept only once a
// caller has verified the token in full, from which every later caller
// checks it again against its own trust.
package statuscache

import (
	"container/list"
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"sync"
	"time"
)

// Defaults for Options' zero values.
const (
	DefaultMaxEntries    = 256
	DefaultMaxBytes      = 64 << 20
	DefaultMaxAge        = 5 * time.Minute
	DefaultMaxFailureAge = 30 * time.Second
)

// Options bounds a Cache; a zero or negative field means its default.
type Options struct {
	MaxEntries int
	MaxBytes   int64
	MaxAge     time.Duration
	// MaxFailureAge is how long a failure is kept; never longer than
	// MaxAge.
	MaxFailureAge time.Duration
	// Now is the clock entries expire by; nil means time.Now.
	Now func() time.Time
}

// Verified is what a caller's verification of a token tells the cache:
// the token's iat, exp and ttl, which bound how long it's kept, and a
// memo of what the verification found that depends on the token's
// bytes alone, which later callers Recheck, with its size in bytes.
type Verified struct {
	Iat       int64
	Exp, TTL  *int64
	Memo      any
	MemoBytes int
}

// Verify verifies token as the calling checker would without a cache.
type Verify func(token []byte) (Verified, error)

// Recheck checks the token another caller's Verify made memo of as the
// calling checker would check those bytes without a cache: it redoes
// every check that depends on the caller — its trust, options and
// clock — and skips only what depends on the bytes alone, which memo
// holds.
type Recheck func(memo any) error

// Fetch fetches a token's bytes.
type Fetch func(context.Context) ([]byte, error)

type key struct{ uri, mediaType string }

type flightKey struct {
	key
	// policy names the fetcher's configuration: callers with different
	// fetch policies don't share a fetch, or its failure.
	policy string
}

// entry is a verified token's memo, under key, or a failure, under
// failure: a fetch's error, or bytes a check refused.
type entry struct {
	key     key
	failure *flightKey
	digest  [sha256.Size]byte
	memo    any
	err     error
	// token is the refused bytes, kept for other checks to verify
	// without fetching them again; nil when they're the verified
	// entry's under key, whose Recheck stands.
	token   []byte
	at      time.Time
	size    int64
	expires time.Time
	elem    *list.Element
}

type flight struct {
	done   chan struct{}
	token  []byte
	digest [sha256.Size]byte
	at     time.Time
	err    error

	// turn is held by the caller verifying token, so that callers
	// sharing the fetch verify it once: the first whose Verify passes
	// sets memo, and the rest Recheck that.
	turn chan struct{}
	memo any
	ok   bool

	// Guarded by Cache.mu.
	fetched bool
	users   int
}

// Cache is safe for concurrent use.
type Cache struct {
	opts Options

	mu       sync.Mutex
	entries  map[key]*entry
	failures map[flightKey]*entry
	lru      *list.List // of *entry, most recently used first
	bytes    int64
	flights  map[flightKey]*flight
}

// New returns an empty Cache bounded by opts.
func New(opts Options) *Cache {
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = DefaultMaxEntries
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = DefaultMaxBytes
	}
	if opts.MaxAge <= 0 {
		opts.MaxAge = DefaultMaxAge
	}
	if opts.MaxFailureAge <= 0 {
		opts.MaxFailureAge = DefaultMaxFailureAge
	}
	opts.MaxFailureAge = min(opts.MaxFailureAge, opts.MaxAge)
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Cache{
		opts: opts, entries: map[key]*entry{}, failures: map[flightKey]*entry{},
		lru: list.New(), flights: map[flightKey]*flight{},
	}
}

// Unwrap is the engine behind a *statuslist.Cache, nil for a nil one.
// statuslist sets it: identifierlist can't reach the Cache's
// unexported field, and an exported accessor would let any caller
// store a memo no check verified.
var Unwrap func(cache any) *Cache

// errStale has a check fetch afresh bytes a failure kept past what
// they allow.
var errStale = errors.New("statuscache: stale")

// Check runs recheck on the memo cached for uri and mediaType, if one
// is and hasn't expired, and returns nil when it passes. Otherwise —
// nothing cached, the entry expired, or recheck refused it — it
// fetches the token (one fetch for concurrent callers with the same
// policy), and verifies it: the first of those callers whose verify
// passes stores its memo, which the others recheck. An expired entry
// is never used: a failed refetch fails the check.
//
// A cached memo recheck refuses is fetched afresh rather than refused
// outright, since the list may have been reissued since: the cache
// never fails a check that would pass without it, beyond what its
// MaxAge allows, and its MaxFailureAge for a failure. A failed fetch
// fails every check with its policy for MaxFailureAge, and bytes a
// check refused are verified again by each check in that time instead
// of fetched, or, if they're the cached entry's, refused with its
// recheck's error.
func (c *Cache) Check(ctx context.Context, uri, mediaType, policy string, fetch Fetch, verify Verify, recheck Recheck) error {
	// A check whose caller has given up fails, as a fetch would, also
	// when the token is cached.
	if err := ctx.Err(); err != nil {
		return err
	}
	k := key{uri, mediaType}
	fk := flightKey{k, policy}
	hit, memo := c.lookup(k)
	var hitErr error
	if hit != nil {
		if hitErr = recheck(memo); hitErr == nil {
			return nil
		}
	}
	if failed := c.failure(fk); failed != nil {
		switch {
		case failed.err != nil:
			return failed.err
		case hit != nil && hit.digest == failed.digest:
			// The cached bytes, fetched again since and refused.
			return hitErr
		case failed.token != nil:
			if err := c.verifyKept(k, failed, verify); !errors.Is(err, errStale) {
				return err
			}
		}
	}
	f, err := c.fetch(ctx, fk, fetch)
	if err != nil {
		return err
	}
	defer c.leave(fk, f)
	return c.settle(ctx, k, fk, f, verify, recheck)
}

// lookup is the unexpired entry under k, and its memo; an expired
// entry is removed.
func (c *Cache) lookup(k key) (*entry, any) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, nil
	}
	if !now.Before(e.expires) {
		c.remove(e)
		return nil, nil
	}
	c.lru.MoveToFront(e.elem)
	return e, e.memo
}

// failure is the unexpired failure under fk; an expired one is
// removed. Its fields don't change once it's stored.
func (c *Cache) failure(fk flightKey) *entry {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	f, ok := c.failures[fk]
	if !ok {
		return nil
	}
	if !now.Before(f.expires) {
		c.remove(f)
		return nil
	}
	c.lru.MoveToFront(f.elem)
	return f
}

// verifyKept verifies the bytes a failure kept, and stores them once
// verify passes. It returns errStale when they're older than they may
// be used: a fresh fetch's are then needed.
func (c *Cache) verifyKept(k key, failed *entry, verify Verify) error {
	v, err := verify(failed.token)
	if err != nil {
		return err
	}
	if !c.opts.Now().Before(c.expiry(v, failed.at)) {
		return errStale
	}
	c.store(k, failed.digest, v, failed.at)
	return nil
}

// fetch runs fetch once for every concurrent caller with fk, and
// returns its flight once the fetch is done; the caller then settles
// it, and leaves it. The fetch doesn't end with the context of the
// caller that started it, so that caller's cancellation doesn't fail
// the others: each waits for it or for its own ctx. The fetcher's HTTP
// timeout bounds it. A failed fetch is kept, as a failure, for
// MaxFailureAge.
func (c *Cache) fetch(ctx context.Context, fk flightKey, fetch Fetch) (*flight, error) {
	c.mu.Lock()
	f, ok := c.flights[fk]
	if !ok {
		f = &flight{done: make(chan struct{}), turn: make(chan struct{}, 1)}
		c.flights[fk] = f
		detached := context.WithoutCancel(ctx)
		go func() {
			token, err := fetch(detached)
			at := c.opts.Now()
			var digest [sha256.Size]byte
			if err == nil {
				digest = sha256.Sum256(token)
			}
			c.mu.Lock()
			f.token, f.digest, f.at, f.err, f.fetched = token, digest, at, err, true
			if err != nil {
				c.storeFailure(&entry{failure: &fk, err: err, at: at})
			}
			if err != nil || f.users == 0 {
				c.endFlight(fk, f)
			}
			c.mu.Unlock()
			close(f.done)
		}()
	}
	f.users++
	c.mu.Unlock()
	select {
	case <-f.done:
		if f.err != nil {
			c.leave(fk, f)
			return nil, f.err
		}
		return f, nil
	case <-ctx.Done():
		c.leave(fk, f)
		return nil, ctx.Err()
	}
}

// settle verifies f's token for the caller: with verify if no caller
// sharing f has passed it yet, storing its memo once it does, and with
// recheck on that memo otherwise. Bytes a check refuses are kept as a
// failure. New callers join f until its first verification ends, so
// that a token is verified once however many checks wait for it.
func (c *Cache) settle(ctx context.Context, k key, fk flightKey, f *flight, verify Verify, recheck Recheck) error {
	select {
	case f.turn <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if f.ok {
		memo := f.memo
		<-f.turn
		if err := recheck(memo); err != nil {
			c.refuse(fk, f)
			return err
		}
		return nil
	}
	v, err := verify(f.token)
	if err == nil {
		f.memo, f.ok = v.Memo, true
		c.store(k, f.digest, v, f.at)
	} else {
		c.refuse(fk, f)
	}
	c.mu.Lock()
	c.endFlight(fk, f)
	c.mu.Unlock()
	<-f.turn
	return err
}

// leave is a caller done with f: the last to leave a fetched flight
// ends it, so that no later caller joins a fetch that may be old.
func (c *Cache) leave(fk flightKey, f *flight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	f.users--
	if f.users == 0 && f.fetched {
		c.endFlight(fk, f)
	}
}

// endFlight has later callers with fk fetch afresh rather than join f;
// c.mu is held.
func (c *Cache) endFlight(fk flightKey, f *flight) {
	if c.flights[fk] == f {
		delete(c.flights, fk)
	}
}

// expiry is when a token verified as v, fetched at, leaves the cache:
// the earliest of its exp, its iat plus ttl, and at plus MaxAge.
func (c *Cache) expiry(v Verified, at time.Time) time.Time {
	expires := at.Add(c.opts.MaxAge)
	if v.Exp != nil {
		expires = earlier(expires, time.Unix(*v.Exp, 0))
	}
	if v.TTL != nil && *v.TTL > 0 && v.Iat <= math.MaxInt64-*v.TTL {
		expires = earlier(expires, time.Unix(v.Iat+*v.TTL, 0))
	}
	return expires
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// store caches the memo of the token with digest, verified as v and
// fetched at, under k, unless it has already expired or is larger than
// the whole cache.
func (c *Cache) store(k key, digest [sha256.Size]byte, v Verified, at time.Time) {
	expires := c.expiry(v, at)
	size := int64(max(v.MemoBytes, 0))
	if !c.opts.Now().Before(expires) || size > c.opts.MaxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[k]; ok {
		// The same bytes, fetched again: kept as long as the new fetch
		// allows.
		if e.digest == digest {
			e.expires = expires
			c.lru.MoveToFront(e.elem)
			return
		}
		c.remove(e)
	}
	c.insert(&entry{key: k, digest: digest, memo: v.Memo, size: size, expires: expires})
}

// refuse keeps f's token, which a check refused, as a failure under fk,
// unless the token is the verified entry's, whose recheck then stands.
func (c *Cache) refuse(fk flightKey, f *flight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	failure := &entry{failure: &fk, digest: f.digest, at: f.at}
	if e, ok := c.entries[fk.key]; !ok || e.digest != f.digest {
		failure.token, failure.size = f.token, int64(len(f.token))
	}
	if old, ok := c.failures[fk]; ok && old.digest == failure.digest && old.err == nil {
		return
	}
	c.storeFailure(failure)
}

// storeFailure keeps failure for MaxFailureAge after its fetch; c.mu
// is held.
func (c *Cache) storeFailure(failure *entry) {
	if old, ok := c.failures[*failure.failure]; ok {
		c.remove(old)
	}
	failure.expires = failure.at.Add(c.opts.MaxFailureAge)
	if !c.opts.Now().Before(failure.expires) || failure.size > c.opts.MaxBytes {
		return
	}
	c.insert(failure)
}

// insert adds e, and evicts the least recently used entries until the
// cache is within its bounds; c.mu is held.
func (c *Cache) insert(e *entry) {
	e.elem = c.lru.PushFront(e)
	if e.failure != nil {
		c.failures[*e.failure] = e
	} else {
		c.entries[e.key] = e
	}
	c.bytes += e.size
	for len(c.entries)+len(c.failures) > c.opts.MaxEntries || c.bytes > c.opts.MaxBytes {
		c.remove(c.lru.Back().Value.(*entry))
	}
}

// remove drops e; c.mu is held.
func (c *Cache) remove(e *entry) {
	c.lru.Remove(e.elem)
	if e.failure != nil {
		delete(c.failures, *e.failure)
	} else {
		delete(c.entries, e.key)
	}
	c.bytes -= e.size
}

// Purge drops every entry and failure.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	clear(c.failures)
	c.lru.Init()
	c.bytes = 0
}

// Len is how many verified entries c holds, and the total size of
// everything it holds, failures included.
func (c *Cache) Len() (entries int, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes
}
