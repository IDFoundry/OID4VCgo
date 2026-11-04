// Package statuscache is the engine behind statuslist.Cache, which
// identifierlist's Checker uses too: a bounded cache of status list
// tokens' bytes, keyed by uri and media type, that stores a token only
// once a caller has verified it, and has every caller verify a token
// it's handed, cached or not.
package statuscache

import (
	"bytes"
	"container/list"
	"context"
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
// memo of the token's decoded form that later verifications of the same
// bytes may reuse, with its size in bytes.
type Verified struct {
	Iat       int64
	Exp, TTL  *int64
	Memo      any
	MemoBytes int
}

// Verify verifies token as the calling checker would without a cache,
// given the memo stored with these bytes, if any (nil otherwise).
type Verify func(token []byte, memo any) (Verified, error)

// Fetch fetches a token's bytes.
type Fetch func(context.Context) ([]byte, error)

type key struct{ uri, mediaType string }

type flightKey struct {
	key
	// policy names the fetcher's configuration: callers with different
	// fetch policies don't share a fetch.
	policy string
}

type entry struct {
	key     key
	token   []byte
	memo    any
	size    int64
	expires time.Time
	elem    *list.Element
}

type flight struct {
	done  chan struct{}
	token []byte
	at    time.Time
	err   error
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
// store a token no check verified.
var Unwrap func(cache any) *Cache

// Check runs verify on the token cached for uri and mediaType, if one
// is and hasn't expired, and returns nil when it passes. Otherwise —
// nothing cached, the entry expired, or verify refused it — it fetches
// the token (one fetch for concurrent callers with the same policy),
// verifies it, and stores it once verify passes. Errors are never
// cached, and an expired entry is never used: a failed refetch fails
// the check.
//
// A cached token verify refuses is fetched afresh rather than refused
// outright, since the list may have been reissued since: the cache never
// fails a check that would pass without it, beyond what its MaxAge
// allows.
func (c *Cache) Check(ctx context.Context, uri, mediaType, policy string, fetch Fetch, verify Verify) error {
	// A check whose caller has given up fails, as a fetch would, also
	// when the token is cached.
	if err := ctx.Err(); err != nil {
		return err
	}
	k := key{uri, mediaType}
	if token, memo, ok := c.lookup(k); ok {
		if _, err := verify(token, memo); err == nil {
			return nil
		}
	}
	token, at, err := c.fetch(ctx, flightKey{k, policy}, fetch)
	if err != nil {
		return err
	}
	v, err := verify(token, c.memoFor(k, token))
	if err != nil {
		return err
	}
	c.store(k, token, v, at)
	return nil
}

// lookup is the unexpired token cached under k, and its memo; an
// expired entry is removed.
func (c *Cache) lookup(k key) ([]byte, any, bool) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, nil, false
	}
	if !now.Before(e.expires) {
		c.remove(e)
		return nil, nil, false
	}
	c.lru.MoveToFront(e.elem)
	return e.token, e.memo, true
}

// memoFor is the memo stored with token under k, if the entry there
// holds these very bytes: a concurrent caller sharing the fetch may
// have stored them already.
func (c *Cache) memoFor(k key, token []byte) any {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[k]; ok && bytes.Equal(e.token, token) {
		return e.memo
	}
	return nil
}

// fetch runs fetch once for every concurrent caller with fk. The fetch
// doesn't end with the context of the caller that started it, so that
// caller's cancellation doesn't fail the others: each waits for it or
// for its own ctx. The fetcher's HTTP timeout bounds it.
func (c *Cache) fetch(ctx context.Context, fk flightKey, fetch Fetch) ([]byte, time.Time, error) {
	c.mu.Lock()
	f, ok := c.flights[fk]
	if !ok {
		f = &flight{done: make(chan struct{})}
		c.flights[fk] = f
		detached := context.WithoutCancel(ctx)
		go func() {
			f.token, f.err = fetch(detached)
			f.at = c.opts.Now()
			c.mu.Lock()
			delete(c.flights, fk)
			c.mu.Unlock()
			close(f.done)
		}()
	}
	c.mu.Unlock()
	select {
	case <-f.done:
		return f.token, f.at, f.err
	case <-ctx.Done():
		return nil, time.Time{}, ctx.Err()
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

// store caches token, verified as v and fetched at, under k, unless it
// has already expired or is larger than the whole cache, and evicts the
// least recently used entries until the cache is within its bounds.
func (c *Cache) store(k key, token []byte, v Verified, at time.Time) {
	expires := c.expiry(v, at)
	size := int64(len(token)) + int64(max(v.MemoBytes, 0))
	if !c.opts.Now().Before(expires) || size > c.opts.MaxBytes {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[k]; ok {
		if bytes.Equal(e.token, token) {
			return
		}
		c.remove(e)
	}
	e := &entry{key: k, token: token, memo: v.Memo, size: size, expires: expires}
	e.elem = c.lru.PushFront(e)
	c.entries[k] = e
	c.bytes += size
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
