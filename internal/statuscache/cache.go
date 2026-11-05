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
	"math"
	"sync"
	"time"
)

// Defaults for Options' zero values.
const (
	DefaultMaxEntries = 256
	DefaultMaxBytes   = 64 << 20
	DefaultMaxAge     = 5 * time.Minute
)

// Options bounds a Cache; a zero or negative field means its default.
type Options struct {
	MaxEntries int
	MaxBytes   int64
	MaxAge     time.Duration
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
	// fetch policies don't share a fetch.
	policy string
}

// entry is a verified token's memo.
type entry struct {
	key     key
	digest  [sha256.Size]byte
	memo    any
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

	mu      sync.Mutex
	entries map[key]*entry
	lru     *list.List // of *entry, most recently used first
	bytes   int64
	flights map[flightKey]*flight
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
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Cache{opts: opts, entries: map[key]*entry{}, lru: list.New(), flights: map[flightKey]*flight{}}
}

// Unwrap is the engine behind a *statuslist.Cache, nil for a nil one.
// statuslist sets it: identifierlist can't reach the Cache's
// unexported field, and an exported accessor would let any caller
// store a memo no check verified.
var Unwrap func(cache any) *Cache

// Check runs recheck on the memo cached for uri and mediaType, if one
// is and hasn't expired, and returns nil when it passes. Otherwise —
// nothing cached, the entry expired, or recheck refused it — it
// fetches the token (one fetch for concurrent callers with the same
// policy), and verifies it: the first of those callers whose verify
// passes stores its memo, which the others recheck. Errors are never
// cached, and an expired entry is never used: a failed refetch fails
// the check.
//
// A cached memo recheck refuses is fetched afresh rather than refused
// outright, since the list may have been reissued since: the cache
// never fails a check that would pass without it, beyond what its
// MaxAge allows.
func (c *Cache) Check(ctx context.Context, uri, mediaType, policy string, fetch Fetch, verify Verify, recheck Recheck) error {
	// A check whose caller has given up fails, as a fetch would, also
	// when the token is cached.
	if err := ctx.Err(); err != nil {
		return err
	}
	k := key{uri, mediaType}
	fk := flightKey{k, policy}
	if memo, ok := c.lookup(k); ok && recheck(memo) == nil {
		return nil
	}
	f, err := c.fetch(ctx, fk, fetch)
	if err != nil {
		return err
	}
	defer c.leave(fk, f)
	return c.settle(ctx, k, fk, f, verify, recheck)
}

// lookup is the unexpired memo cached under k; an expired entry is
// removed.
func (c *Cache) lookup(k key) (any, bool) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, false
	}
	if !now.Before(e.expires) {
		c.remove(e)
		return nil, false
	}
	c.lru.MoveToFront(e.elem)
	return e.memo, true
}

// fetch runs fetch once for every concurrent caller with fk, and
// returns its flight once the fetch is done; the caller then settles
// it, and leaves it. The fetch doesn't end with the context of the
// caller that started it, so that caller's cancellation doesn't fail
// the others: each waits for it or for its own ctx. The fetcher's HTTP
// timeout bounds it.
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
// recheck on that memo otherwise. New callers join f until its first
// verification ends, so that a token is verified once however many
// checks wait for it.
func (c *Cache) settle(ctx context.Context, k key, fk flightKey, f *flight, verify Verify, recheck Recheck) error {
	select {
	case f.turn <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	if f.ok {
		memo := f.memo
		<-f.turn
		return recheck(memo)
	}
	v, err := verify(f.token)
	if err == nil {
		f.memo, f.ok = v.Memo, true
		c.store(k, f.digest, v, f.at)
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

// insert adds e, and evicts the least recently used entries until the
// cache is within its bounds; c.mu is held.
func (c *Cache) insert(e *entry) {
	e.elem = c.lru.PushFront(e)
	c.entries[e.key] = e
	c.bytes += e.size
	for len(c.entries) > c.opts.MaxEntries || c.bytes > c.opts.MaxBytes {
		c.remove(c.lru.Back().Value.(*entry))
	}
}

// remove drops e; c.mu is held.
func (c *Cache) remove(e *entry) {
	c.lru.Remove(e.elem)
	delete(c.entries, e.key)
	c.bytes -= e.size
}

// Purge drops every entry.
func (c *Cache) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.entries)
	c.lru.Init()
	c.bytes = 0
}

// Len is how many entries c holds, and their total size.
func (c *Cache) Len() (entries int, size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries), c.bytes
}
