package statuslist

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/statuscache"
)

// CacheOptions bounds a Cache. A zero or negative field means its
// default.
type CacheOptions struct {
	// MaxEntries is how many tokens the Cache holds at most; the least
	// recently used is dropped first. Zero means 256.
	MaxEntries int

	// MaxBytes bounds the tokens' total size, with what the Cache keeps
	// of each decoded; a token larger than that alone isn't cached.
	// Zero means 64 MiB.
	MaxBytes int64

	// MaxAge is the longest a token is kept after it was fetched, also
	// when it sets no ttl (draft-14 §5.1): until then a status changed
	// at its issuer isn't seen. Zero means DefaultCacheMaxAge.
	MaxAge time.Duration

	// Now is the clock entries expire by; nil means time.Now. Each check
	// still verifies a token's times at its own VerifyOptions.Now.
	Now func() time.Time
}

// DefaultCacheMaxAge is CacheOptions.MaxAge's default: 5 minutes.
const DefaultCacheMaxAge = statuscache.DefaultMaxAge

// Cache keeps fetched Status List Tokens for a Checker, or for several
// sharing it, so a list several credentials reference, or one checked
// again soon after, isn't fetched each time: for no longer than the
// token's ttl allows. An identifierlist.Checker takes one too.
//
// It caches a token's bytes, by its uri and media type, and only once a
// check has verified it in full. It keeps a token until the earliest of
// its exp, its iat plus its ttl, and MaxAge after it was fetched. A
// check failure is never cached, and an expired token is never used: a
// check that can't fetch it afresh fails, however recently it was
// valid.
//
// Every check verifies the cached token again, with its own Checker's
// Roots and Options — the signer's chain and binding to the Referenced
// Token's issuer, its revocation, the signature, and the token's times
// at that check's Now — so a token one Checker accepted never satisfies
// another's trust by being cached. A token a check refuses is fetched
// afresh, as without a Cache. Only the token's decoded claims and
// decompressed list are reused, since they depend on its bytes alone:
// a cached check costs a signature and a chain verification.
//
// Concurrent checks of a token that isn't cached share one fetch, when
// their Fetchers are configured alike.
//
// A Cache is safe for concurrent use. The claims a check through one
// returns may share memory with it: treat them as read-only.
type Cache struct {
	engine *statuscache.Cache
}

// NewCache returns an empty Cache bounded by opts.
func NewCache(opts CacheOptions) *Cache {
	return &Cache{engine: statuscache.New(statuscache.Options{
		MaxEntries: opts.MaxEntries, MaxBytes: opts.MaxBytes, MaxAge: opts.MaxAge, Now: opts.Now,
	})}
}

// Purge drops every token c keeps: for an application told a status
// changed, say, so that its next check fetches the list afresh.
func (c *Cache) Purge() { c.engine.Purge() }

func init() {
	statuscache.Unwrap = func(v any) *statuscache.Cache {
		if c, ok := v.(*Cache); ok && c != nil {
			return c.engine
		}
		return nil
	}
}

// tokenMemo is what a Cache keeps of a verified token's bytes beyond
// the bytes themselves: its parsed claims, and its list decompressed.
// Both depend on the bytes alone, which digest names.
type tokenMemo struct {
	digest  [sha256.Size]byte
	parsed  parsedClaims
	decoded *Decoded // nil when the list didn't decompress whole
}

// newTokenMemo is token's memo, given its parsed claims.
func newTokenMemo(token []byte, parsed parsedClaims) *tokenMemo {
	m := &tokenMemo{digest: sha256.Sum256(token), parsed: parsed}
	if decoded, err := parsed.claims.StatusList.Decode(); err == nil {
		m.decoded = &decoded
	}
	return m
}

// of is m if it was made from token's bytes, nil otherwise.
func (m *tokenMemo) of(token []byte) *tokenMemo {
	if m == nil || m.digest != sha256.Sum256(token) {
		return nil
	}
	return m
}

// size is roughly how many bytes m holds.
func (m *tokenMemo) size() int {
	n := len(m.parsed.claims.Sub) + len(m.parsed.claims.StatusList.Lst) + len(m.parsed.claims.StatusList.AggregationURI) + len(m.parsed.iss)
	if m.decoded != nil {
		n += len(m.decoded.Packed)
	}
	return n
}

// parsedClaims is m's parsed claims, nil for a nil m.
func (m *tokenMemo) parsedClaims() *parsedClaims {
	if m == nil {
		return nil
	}
	return &m.parsed
}

// decodedList is m's decompressed list, nil for a nil m.
func (m *tokenMemo) decodedList() *Decoded {
	if m == nil {
		return nil
	}
	return m.decoded
}

// check is Checker.check through c: verify checks a token, given its
// memo if c has one.
func (c *Cache) check(ctx context.Context, fetcher Fetcher, uri, mediaType string, verify func([]byte, *tokenMemo) (StatusType, parsedClaims, error)) (StatusType, TokenClaims, error) {
	var status StatusType
	var claims TokenClaims
	limit := fetcher.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxTokenBytes
	}
	err := c.engine.Check(ctx, uri, mediaType, fetcher.cacheKey(),
		func(ctx context.Context) ([]byte, error) { return fetcher.Fetch(ctx, uri, mediaType) },
		func(token []byte, memo any) (statuscache.Verified, error) {
			// A token another Checker's Fetcher fetched may be larger than
			// this one's would.
			if len(token) > limit {
				return statuscache.Verified{}, fmt.Errorf("statuslist: fetch %s: token exceeds %d bytes", uri, limit)
			}
			m, _ := memo.(*tokenMemo)
			m = m.of(token)
			s, parsed, err := verify(token, m)
			if err != nil {
				return statuscache.Verified{}, err
			}
			status, claims = s, parsed.claims.clone()
			if m == nil {
				m = newTokenMemo(token, parsed)
			}
			return statuscache.Verified{
				Iat: parsed.claims.Iat, Exp: parsed.claims.Exp, TTL: parsed.claims.TTL,
				Memo: m, MemoBytes: m.size(),
			}, nil
		})
	if err != nil {
		return 0, TokenClaims{}, err
	}
	return status, claims, nil
}

// clone is c with its own exp and ttl, so a caller changing them
// doesn't change a Cache's.
func (c TokenClaims) clone() TokenClaims {
	if c.Exp != nil {
		exp := *c.Exp
		c.Exp = &exp
	}
	if c.TTL != nil {
		ttl := *c.TTL
		c.TTL = &ttl
	}
	return c
}

// cacheKey names f's configuration, so that only checks whose Fetchers
// would fetch alike share a fetch (the cached token is verified by each
// check whichever fetched it).
func (f Fetcher) cacheKey() string {
	return fmt.Sprintf("%p/%d/%t/%t/%t/%t", f.HTTP, f.MaxBytes, f.AllowLoopback, f.AllowPrivate, f.AllowProxy, f.UncheckedTransport)
}
