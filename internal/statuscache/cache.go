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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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
	// Store, when set, keeps the tokens the cache verified across
	// processes (statuslist.CacheStore), to revalidate rather than
	// download them again.
	Store Store
	// StoreKey, when set, authenticates the records Store keeps
	// (HMAC-SHA256): one that doesn't verify is dropped. Without it, a
	// record is trusted on a 304 only within MaxAge of its token's iat
	// (storedUsable).
	StoreKey []byte
}

// Store keeps named records across processes; statuslist.CacheStore
// documents it.
type Store interface {
	Load(name string) ([]byte, error)
	Save(name string, record []byte) error
	Remove(name string) error
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

// Validators are what a token was fetched with that a later fetch can
// revalidate it by (RFC 9110 §8.8): its response's ETag and
// Last-Modified, each empty when it had none.
type Validators struct{ ETag, LastModified string }

// Fetched is a fetch's outcome.
type Fetched struct {
	// Token is the token's bytes; nil when NotModified.
	Token []byte
	// NotModified is a 304 to a conditional fetch: the token held is
	// still the one served.
	NotModified bool
	// Validators are the response's, for the next fetch.
	Validators Validators
	// MaxAge is how long the response says it's fresh for (its
	// Cache-Control max-age less its Age), when it says.
	MaxAge *time.Duration
}

// Fetch fetches a token. With held validators that aren't zero it
// fetches conditionally, and a 304 is Fetched.NotModified; with zero
// ones a 304 is an error.
type Fetch func(ctx context.Context, held Validators) (Fetched, error)

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
	token []byte
	// iat, exp and ttl are the verified token's, which bound how long a
	// fetch that finds it unchanged keeps it.
	iat      int64
	exp, ttl *int64
	fetchMeta
	at      time.Time
	size    int64
	expires time.Time
	elem    *list.Element
}

// fetchMeta is what a fetch's response says about its token beyond its
// bytes.
type fetchMeta struct {
	validators Validators
	maxAge     *time.Duration
}

type flight struct {
	done   chan struct{}
	token  []byte
	digest [sha256.Size]byte
	at     time.Time
	err    error
	fetchMeta
	// prior is the expired entry the fetch revalidated, and
	// notModified that the response found it unchanged.
	prior       *entry
	notModified bool
	// held are the validators the fetch revalidated prior by.
	held Validators
	// stored is the token Options.Store kept, which the fetch
	// revalidated instead, with no prior, and fromStore that the
	// response found it unchanged: token is then stored.Token, verified
	// in full as a fetched one.
	stored    *record
	fromStore bool

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

// FetchConditional fetches uri as a statuslist.Fetcher, fetcher, would,
// asking for mediaType, and revalidates by held when they aren't zero.
// statuslist sets it, so that identifierlist's Checker can fetch
// conditionally without statuslist exporting it.
var FetchConditional func(ctx context.Context, fetcher any, uri, mediaType string, held Validators) (Fetched, error)

// errStale has a check fetch afresh bytes a failure kept past what
// they allow.
var errStale = errors.New("statuscache: stale")

// errStoredUnusable has a check fetch afresh a token Options.Store kept
// that a 304 can't vouch for (storedUsable).
var errStoredUnusable = errors.New("statuscache: the kept token is too old to revalidate")

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
	hit, memo, stale := c.lookup(k)
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
	err := c.fetchAndSettle(ctx, k, fk, fetch, stale, true, verify, recheck)
	if errors.Is(err, errStoredUnusable) {
		// Fetched again without the store's token: unconditionally.
		err = c.fetchAndSettle(ctx, k, fk, fetch, nil, false, verify, recheck)
	}
	return err
}

func (c *Cache) fetchAndSettle(ctx context.Context, k key, fk flightKey, fetch Fetch, stale *entry, useStore bool, verify Verify, recheck Recheck) error {
	f, err := c.fetch(ctx, fk, fetch, stale, useStore)
	if err != nil {
		return err
	}
	defer c.leave(fk, f)
	return c.settle(ctx, k, fk, f, verify, recheck)
}

// storedUsable reports whether the token Options.Store kept, verified
// as v, may be used on a 304 to the validators its record names. With
// Options.StoreKey the record was authenticated when it was loaded, so
// it may. Without one, anyone able to write the store could pair an
// older token, validly signed, with the validators the server serves
// now, which are public: the token is then used only within MaxAge of
// its iat (and its iat plus ttl, if shorter), as long as one a fetch
// just returned could be kept.
func (c *Cache) storedUsable(v Verified) bool {
	if len(c.opts.StoreKey) > 0 {
		return true
	}
	iat := time.Unix(v.Iat, 0)
	limit := iat.Add(c.opts.MaxAge)
	if v.TTL != nil && *v.TTL > 0 && v.Iat <= math.MaxInt64-*v.TTL {
		limit = earlier(limit, time.Unix(v.Iat+*v.TTL, 0))
	}
	return c.opts.Now().Before(limit)
}

// lookup is the unexpired entry under k, and its memo, or else the
// expired one a fetch may revalidate, stale. An expired entry without
// validators is removed; one with them is kept, unused, until a fetch
// finds it unchanged or replaces it.
func (c *Cache) lookup(k key) (hit *entry, memo any, stale *entry) {
	now := c.opts.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[k]
	if !ok {
		return nil, nil, nil
	}
	if !now.Before(e.expires) {
		if e.validators == (Validators{}) {
			c.remove(e)
			return nil, nil, nil
		}
		return nil, nil, e
	}
	c.lru.MoveToFront(e.elem)
	return e, e.memo, nil
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
	if !c.opts.Now().Before(c.expiry(v, failed.at, failed.maxAge)) {
		return errStale
	}
	c.store(k, failed.digest, v, failed.at, failed.fetchMeta)
	return nil
}

// fetch runs fetch once for every concurrent caller with fk, and
// returns its flight once the fetch is done; the caller then settles
// it, and leaves it. The flight that starts it revalidates stale, when
// set, by its validators. The fetch doesn't end with the context of the
// caller that started it, so that caller's cancellation doesn't fail
// the others: each waits for it or for its own ctx. The fetcher's HTTP
// timeout bounds it. A failed fetch is kept, as a failure, for
// MaxFailureAge. With useStore false, a token Options.Store kept isn't
// revalidated: the fetch is unconditional, unless stale is set.
func (c *Cache) fetch(ctx context.Context, fk flightKey, fetch Fetch, stale *entry, useStore bool) (*flight, error) {
	c.mu.Lock()
	f, ok := c.flights[fk]
	if !ok {
		f = &flight{done: make(chan struct{}), turn: make(chan struct{}, 1)}
		var held Validators
		if stale != nil {
			// Read under c.mu, which store changes them under.
			f.prior, held = stale, stale.validators
			f.held = held
		}
		c.flights[fk] = f
		detached := context.WithoutCancel(ctx)
		go func() {
			if f.prior == nil && useStore {
				if f.stored = c.load(fk.key); f.stored != nil {
					held = f.stored.validators()
				}
			}
			res, err := fetch(detached, held)
			at := c.opts.Now()
			var digest [sha256.Size]byte
			fromStore := false
			switch {
			case err != nil:
			case res.NotModified && f.stored != nil:
				// The stored token is still the one served: verified in
				// full, as a fetched one.
				res.Token, res.NotModified, fromStore = f.stored.Token, false, true
				if res.Validators == (Validators{}) {
					res.Validators = held
				}
				digest = sha256.Sum256(res.Token)
			case res.NotModified && f.prior == nil:
				err = errors.New("statuscache: a 304 to an unconditional fetch")
			case res.NotModified:
				digest = f.prior.digest
				if res.Validators == (Validators{}) {
					// A 304 needn't repeat them (RFC 9110 §15.4.5).
					res.Validators = held
				}
			default:
				digest = sha256.Sum256(res.Token)
			}
			c.mu.Lock()
			f.token, f.digest, f.at, f.err, f.fetched = res.Token, digest, at, err, true
			f.notModified, f.fromStore, f.fetchMeta = res.NotModified, fromStore, fetchMeta{validators: res.Validators, maxAge: res.MaxAge}
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
	if f.notModified {
		return c.settleNotModified(k, fk, f, recheck)
	}
	v, err := verify(f.token)
	if err == nil && f.fromStore && !c.storedUsable(v) {
		// Unauthenticated, and too old for a 304 to vouch for it: a
		// 304 confirms the validators the record names, not the bytes
		// kept with them. The caller downloads the token instead.
		c.unsave(k)
		err = errStoredUnusable
	}
	if err == nil {
		f.memo, f.ok = v.Memo, true
		c.store(k, f.digest, v, f.at, f.fetchMeta)
		c.save(k, f)
	} else if f.fromStore {
		// Bytes the store kept that don't verify, whatever the server's
		// validators say: the next check downloads the token, as one
		// whose memo a 304 kept that a check refuses.
		c.unsave(k)
	} else {
		c.refuse(fk, f)
	}
	c.mu.Lock()
	c.endFlight(fk, f)
	c.mu.Unlock()
	<-f.turn
	return err
}

// settleNotModified is settle of a flight whose fetch found its prior
// entry unchanged: the caller holds f.turn. The entry's memo is checked
// again, as a cached one would be, and kept for as long as the
// response allows once a check passes it. One no check passes is
// dropped, so that the next check fetches the token in full.
func (c *Cache) settleNotModified(k key, fk flightKey, f *flight, recheck Recheck) error {
	prior := f.prior
	err := recheck(prior.memo)
	if err == nil {
		f.memo, f.ok = prior.memo, true
		c.store(k, prior.digest, Verified{Iat: prior.iat, Exp: prior.exp, TTL: prior.ttl, Memo: prior.memo, MemoBytes: int(prior.size)}, f.at, f.fetchMeta)
		if f.validators != f.held {
			c.resave(k, prior.digest, f.validators)
		} else {
			c.touch(k)
		}
	} else {
		c.mu.Lock()
		if c.entries[k] == prior {
			c.remove(prior)
		}
		c.mu.Unlock()
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

// expiry is when a token verified as v, fetched at with a response
// fresh for maxAge, if it said, leaves the cache: the earliest of its
// exp, its iat plus ttl, at plus maxAge, and at plus MaxAge.
func (c *Cache) expiry(v Verified, at time.Time, maxAge *time.Duration) time.Time {
	expires := at.Add(c.opts.MaxAge)
	if maxAge != nil {
		expires = earlier(expires, at.Add(max(*maxAge, 0)))
	}
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
// fetched at with meta, under k, unless it has already expired or is
// larger than the whole cache.
func (c *Cache) store(k key, digest [sha256.Size]byte, v Verified, at time.Time, meta fetchMeta) {
	expires := c.expiry(v, at, meta.maxAge)
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
			e.expires, e.fetchMeta = expires, meta
			c.lru.MoveToFront(e.elem)
			return
		}
		c.remove(e)
	}
	c.insert(&entry{key: k, digest: digest, memo: v.Memo, iat: v.Iat, exp: v.Exp, ttl: v.TTL, fetchMeta: meta, size: size, expires: expires})
}

// refuse keeps f's token, which a check refused, as a failure under fk,
// unless the token is the verified entry's, whose recheck then stands.
func (c *Cache) refuse(fk flightKey, f *flight) {
	c.mu.Lock()
	defer c.mu.Unlock()
	failure := &entry{failure: &fk, digest: f.digest, at: f.at, fetchMeta: f.fetchMeta}
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

// record is what Options.Store keeps of a token: its bytes, and the
// validators its response gave, for the next process to revalidate it
// by. Only a token a check verified in full, whose response gave
// validators, is kept. With Options.StoreKey, MAC authenticates the
// rest (recordMAC).
type record struct {
	URI          string `json:"uri"`
	MediaType    string `json:"media_type"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`
	Token        []byte `json:"token"`
	MAC          []byte `json:"mac,omitempty"`
}

// recordMAC is r's HMAC-SHA256 under key: over a domain separator and
// each of its fields, length-prefixed.
func recordMAC(key []byte, r *record) []byte {
	m := hmac.New(sha256.New, key)
	for _, field := range [][]byte{[]byte("oid4vcgo statuscache record v1"), []byte(r.URI), []byte(r.MediaType), []byte(r.ETag), []byte(r.LastModified), r.Token} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(field)))
		m.Write(n[:])
		m.Write(field)
	}
	return m.Sum(nil)
}

func (r *record) validators() Validators {
	return Validators{ETag: r.ETag, LastModified: r.LastModified}
}

// recordName is the name k's record is kept under.
func recordName(k key) string {
	sum := sha256.Sum256([]byte(k.uri + "\x00" + k.mediaType))
	return hex.EncodeToString(sum[:])
}

// load is the record Options.Store keeps for k, nil when it keeps none
// it can use. The store's failures only cost a download: they're not
// the check's.
func (c *Cache) load(k key) *record {
	if c.opts.Store == nil {
		return nil
	}
	data, err := c.opts.Store.Load(recordName(k))
	if err != nil || data == nil {
		return nil
	}
	var r record
	if json.Unmarshal(data, &r) != nil || r.URI != k.uri || r.MediaType != k.mediaType || len(r.Token) == 0 || r.validators() == (Validators{}) ||
		(len(c.opts.StoreKey) > 0 && !hmac.Equal(r.MAC, recordMAC(c.opts.StoreKey, &r))) {
		c.unsave(k)
		return nil
	}
	return &r
}

// save keeps f's token, which a check verified in full, in
// Options.Store under k, when its response gave validators to
// revalidate it by; when it gave none, a record kept for k is removed.
// A token the store gave back unchanged isn't written again.
func (c *Cache) save(k key, f *flight) {
	if c.opts.Store == nil {
		return
	}
	if f.validators == (Validators{}) {
		if f.stored != nil {
			c.unsave(k)
		}
		return
	}
	if f.fromStore && f.validators == f.stored.validators() {
		return
	}
	c.write(record{URI: k.uri, MediaType: k.mediaType, ETag: f.validators.ETag, LastModified: f.validators.LastModified, Token: f.token})
}

// resave keeps validators for the token with digest that
// Options.Store keeps under k, which a 304 gave with new validators.
func (c *Cache) resave(k key, digest [sha256.Size]byte, validators Validators) {
	r := c.load(k)
	if r == nil || sha256.Sum256(r.Token) != digest {
		return
	}
	if validators == (Validators{}) {
		c.unsave(k)
		return
	}
	r.ETag, r.LastModified = validators.ETag, validators.LastModified
	c.write(*r)
}

func (c *Cache) write(r record) {
	r.MAC = nil
	if len(c.opts.StoreKey) > 0 {
		r.MAC = recordMAC(c.opts.StoreKey, &r)
	}
	data, err := json.Marshal(r)
	if err != nil {
		return
	}
	_ = c.opts.Store.Save(recordName(key{r.URI, r.MediaType}), data)
}

// Toucher is a Store that can mark a record used without rewriting it,
// so that it's evicted after records used less recently.
type Toucher interface {
	Touch(name string) error
}

// touch marks k's record used, when Options.Store can: a 304 for a
// token in memory confirmed it.
func (c *Cache) touch(k key) {
	if t, ok := c.opts.Store.(Toucher); ok {
		_ = t.Touch(recordName(k))
	}
}

func (c *Cache) unsave(k key) {
	if c.opts.Store != nil {
		_ = c.opts.Store.Remove(recordName(k))
	}
}
