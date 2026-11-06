package statuslist

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/statuscache"
)

// CacheOptions bounds a Cache. A zero or negative field means its
// default.
type CacheOptions struct {
	// MaxEntries is how many tokens, and failures, the Cache holds at
	// most; the least recently used is dropped first. Zero means 256.
	MaxEntries int

	// MaxBytes bounds the total size of what the Cache keeps of its
	// tokens, and of the refused tokens it keeps (MaxFailureAge); a
	// token whose share is larger than that alone isn't cached. Zero
	// means 64 MiB.
	//
	// A token's share is about its list decompressed, entries × bits /
	// 8 bytes, plus its lst as it carries it; the token itself isn't
	// kept. A list of 2^24 one-bit entries takes 2 MiB and its lst, a
	// fifth of a MiB to a MiB for 1% to 5% of them revoked at random,
	// so 64 MiB holds about 22 to 27 of those: size it for the lists
	// the Checkers read in the time the tokens are kept.
	MaxBytes int64

	// MaxAge is the longest a token is kept after it was fetched, or
	// revalidated, also when it sets no ttl (draft-14 §5.1): until then
	// a status changed at its issuer isn't seen. Zero means
	// DefaultCacheMaxAge.
	MaxAge time.Duration

	// MaxFailureAge is how long a failed fetch, or a token a check
	// refused, is kept after it was fetched: checks of its uri in that
	// time fail with the fetch's error, or verify the refused token
	// again, rather than fetch it again. Zero means
	// DefaultCacheMaxFailureAge; it's never longer than MaxAge.
	MaxFailureAge time.Duration

	// Now is the clock entries expire by; nil means time.Now. Each check
	// still verifies a token's times at its own VerifyOptions.Now.
	Now func() time.Time

	// Store, when set, keeps the tokens the Cache verifies across
	// processes — an app's launches, say — so that a later process
	// revalidates a token it kept instead of downloading it again
	// (NewDirCacheStore keeps them in a directory). Nil keeps them in
	// memory only.
	Store CacheStore

	// StoreKey, at least 32 random bytes, authenticates the records
	// Store keeps (HMAC-SHA256), so that one anyone else wrote is
	// dropped, not used. Keep it where Store's records aren't, and the
	// same across processes: the platform's keychain or keystore, say.
	// Without it, a kept token is used on a 304 only within MaxAge of
	// its iat (CacheStore). Ignored without Store.
	StoreKey []byte
}

// CacheStore keeps a Cache's tokens across processes, as named records:
// a token's bytes and the ETag and Last-Modified its response gave.
// Only a token a check verified in full, whose response gave either, is
// kept.
//
// What a store gives back is never trusted as it is: a process's first
// check of a list it holds revalidates the kept token with the list's
// server, with If-None-Match and If-Modified-Since, as an expired cached
// one is, and on a 304 verifies the token in full, as a fetched one —
// so a list the server still serves costs a round trip, not its
// download. A 304 confirms the validators a record names, though, not
// the token kept with them, and validators are public: whoever can
// write the store could pair an older token, validly signed, with the
// ones the server serves now. So a record is used only when
// CacheOptions.StoreKey authenticates it, or, without a key, while its
// token is within the Cache's MaxAge of its iat (and its iat plus ttl,
// if sooner) — no older than one a fetch just returned could be kept.
// Otherwise the token is downloaded. A kept token that doesn't verify
// is removed, and downloaded again. A store's failures cost a download
// only: they don't fail a check.
//
// A CacheStore whose records are bounded should evict the least
// recently used first. A store that also has a method Touch(name string)
// error has it called when a 304 confirms a token the Cache holds in
// memory, which reads nothing from the store, so it can count that as a
// use (DirCacheStore does).
//
// A CacheStore must be safe for concurrent use.
type CacheStore interface {
	// Load returns the record kept under name; nil and a nil error, or
	// an error, when none is.
	Load(name string) ([]byte, error)
	// Save keeps record under name, replacing any kept there.
	Save(name string, record []byte) error
	// Remove drops the record kept under name; nil when none is.
	Remove(name string) error
}

// DefaultCacheMaxAge is CacheOptions.MaxAge's default: 5 minutes.
const DefaultCacheMaxAge = statuscache.DefaultMaxAge

// DefaultCacheMaxFailureAge is CacheOptions.MaxFailureAge's default: 30
// seconds.
const DefaultCacheMaxFailureAge = statuscache.DefaultMaxFailureAge

// Cache keeps fetched Status List Tokens for a Checker, or for several
// sharing it, so a list several credentials reference, or one checked
// again soon after, isn't fetched each time: for no longer than the
// token's ttl allows. An identifierlist.Checker takes one too.
//
// It caches a token, by its uri and media type, only once a check has
// verified it in full, and keeps what that check found that depends on
// the token's bytes alone: that its signature verifies under the leaf
// of the signer's chain it carries, that chain, its claims and its list
// decompressed — not the token. It keeps a token until the earliest of
// its exp, its iat plus its ttl, MaxAge after it was fetched, and the
// Cache-Control max-age its response gave, less its Age. An expired
// token is never used: a check that can't fetch it afresh fails,
// however recently it was valid.
//
// A token whose response carried an ETag or Last-Modified is
// revalidated once it expires, with If-None-Match and
// If-Modified-Since: a 304 Not Modified keeps it, checked again as a
// cached one, for as long again as a fresh fetch would — never past its
// own exp or iat plus ttl — so a list its server still serves costs a
// round trip, not its download. A check that refuses the token a 304
// kept fetches it in full.
//
// Every check of a cached token checks it again with its own Checker's
// Roots and Options — the signer's chain to those Roots, its policy and
// binding to the Referenced Token's issuer, its revocation, and the
// token's iss, sub, size and times at that check's Now — so a token one
// Checker accepted never satisfies another's trust by being cached.
// Only what depends on the bytes alone isn't done again: a cached check
// costs a chain verification, not a signature over the whole token, a
// parse or a decompression. A cached token a check refuses is fetched
// afresh, as without a Cache.
//
// Concurrent checks of a token that isn't cached share one fetch, when
// their Fetchers are configured alike, and the first of them to verify
// it decompresses its list for all: the others check it again as a
// cached one.
//
// A failure is kept for MaxFailureAge: a failed fetch fails the checks
// of its uri in that time, and a token a check refused is verified
// again by each of them instead of fetched, and cached once one passes,
// unless they're the cached token's bytes, whose refusal then stands.
//
// A Cache is safe for concurrent use. The claims a check through one
// returns may share memory with it: treat them as read-only.
type Cache struct {
	engine *statuscache.Cache
}

// NewCache returns an empty Cache bounded by opts.
func NewCache(opts CacheOptions) *Cache {
	return &Cache{engine: statuscache.New(statuscache.Options{
		MaxEntries: opts.MaxEntries, MaxBytes: opts.MaxBytes, MaxAge: opts.MaxAge,
		MaxFailureAge: opts.MaxFailureAge, Now: opts.Now, Store: opts.Store,
		StoreKey: slices.Clone(opts.StoreKey),
	})}
}

// Purge drops every token c keeps: for an application told a status
// changed, say, so that its next check fetches the list afresh. Its
// CacheStore's records stay: a check revalidates one before using it.
func (c *Cache) Purge() { c.engine.Purge() }

func init() {
	statuscache.Unwrap = func(v any) *statuscache.Cache {
		if c, ok := v.(*Cache); ok && c != nil {
			return c.engine
		}
		return nil
	}
	statuscache.FetchConditional = func(ctx context.Context, fetcher any, uri, mediaType string, held statuscache.Validators) (statuscache.Fetched, error) {
		f, ok := fetcher.(Fetcher)
		if !ok {
			return statuscache.Fetched{}, errors.New("statuslist: not a Fetcher")
		}
		return f.fetch(ctx, uri, mediaType, held)
	}
}

// tokenMemo is what a Cache keeps of a token a check verified in full:
// what that check found that depends on the token's bytes alone,
// without the bytes — their size, the signer's chain the token carries,
// whose leaf's key its signature verified under, its claims as parsed,
// and its list decompressed.
type tokenMemo struct {
	size int
	cwt  bool
	// chainProtected is whether a CWT token's chain is from its
	// protected header.
	chainProtected bool
	chain          [][]byte
	parsed         parsedClaims
	decoded        *Decoded // nil when the list didn't decompress whole
}

// verifyMemo verifies token, fetched from uri, as checkX5C or, when cwt
// is set, checkCWTX5Chain does short of the status lookup, and returns
// what a Cache keeps of it: its list is decompressed once, for this
// check and the later ones.
func verifyMemo(ctx context.Context, token []byte, cwt bool, roots *x509.CertPool, uri string, opts VerifyOptions) (*tokenMemo, error) {
	var signed signedToken
	var err error
	if cwt {
		signed, err = verifyCWTX5Chain(ctx, token, roots, opts)
	} else {
		signed, err = verifyX5C(ctx, string(token), roots, opts)
	}
	if err != nil {
		return nil, err
	}
	if err := checkSub(signed.parsed.claims, uri); err != nil {
		return nil, err
	}
	m := &tokenMemo{size: len(token), cwt: cwt, chainProtected: signed.chainProtected, parsed: signed.parsed}
	// Copied, so that m doesn't keep the token's bytes alive.
	for _, der := range signed.chain {
		m.chain = append(m.chain, slices.Clone(der))
	}
	if decoded, err := signed.parsed.claims.StatusList.Decode(); err == nil {
		// Trimmed to what it holds: io.ReadAll leaves room to spare.
		if cap(decoded.Packed) > len(decoded.Packed) {
			decoded.Packed = slices.Clone(decoded.Packed)
		}
		m.decoded = &decoded
	}
	return m, nil
}

// recheck checks the token m was made of as verifyMemo does, for
// another check, from m alone: the signer's chain is verified again to
// roots at opts's Now, on a path opts's policy approves and its
// Revocation passes, and bound again to the Referenced Token's issuer,
// and the claims are checked again against opts and uri. What depends
// on the bytes alone — the signature under the chain's leaf, the typ,
// the parse and the decompression — isn't done again.
func (m *tokenMemo) recheck(ctx context.Context, roots *x509.CertPool, uri string, opts VerifyOptions) error {
	opts = opts.atOneInstant()
	trust, err := signerTrust(roots, opts)
	if err != nil {
		return err
	}
	// As a decode under trust.MaxBytes would refuse it.
	if m.size > trust.MaxBytes {
		return fmt.Errorf("statuslist: decode token: %d bytes, over the %d allowed", m.size, trust.MaxBytes)
	}
	// The chain trust.Chain would read: under X5ChainProtectedOnly, none
	// unless it's in the protected header.
	chain := m.chain
	if m.cwt && opts.X5ChainProtectedOnly && !m.chainProtected {
		chain = nil
	}
	if _, _, err := trustedSigner(ctx, trust, chain, m.cwt, opts); err != nil {
		return err
	}
	if err := m.parsed.check(opts); err != nil {
		return err
	}
	return checkSub(m.parsed.claims, uri)
}

// bytes is roughly how many bytes m holds.
func (m *tokenMemo) bytes() int {
	n := len(m.parsed.claims.Sub) + len(m.parsed.claims.StatusList.Lst) + len(m.parsed.claims.StatusList.AggregationURI) + len(m.parsed.iss)
	for _, der := range m.chain {
		n += len(der)
	}
	if m.decoded != nil {
		n += cap(m.decoded.Packed)
	}
	return n
}

// check is Checker.check through c: verify verifies a token fetched for
// ref, and recheck one a check verified before, from its memo; ref's
// status is then read from the memo either passed.
func (c *Cache) check(ctx context.Context, fetcher Fetcher, ref StatusListRef, mediaType string, verify func([]byte) (*tokenMemo, error), recheck func(*tokenMemo) error) (StatusType, TokenClaims, error) {
	limit := fetcher.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxTokenBytes
	}
	var used *tokenMemo
	err := c.engine.Check(ctx, ref.URI, mediaType, fetcher.cacheKey(),
		func(ctx context.Context, held statuscache.Validators) (statuscache.Fetched, error) {
			return fetcher.fetch(ctx, ref.URI, mediaType, held)
		},
		func(token []byte) (statuscache.Verified, error) {
			m, err := verify(token)
			if err != nil {
				return statuscache.Verified{}, err
			}
			used = m
			return statuscache.Verified{
				Iat: m.parsed.claims.Iat, Exp: m.parsed.claims.Exp, TTL: m.parsed.claims.TTL,
				Memo: m, MemoBytes: m.bytes(),
			}, nil
		},
		func(memo any) error {
			m, ok := memo.(*tokenMemo)
			if !ok {
				return errors.New("statuslist: the cached entry isn't a status list token's")
			}
			// A token another Checker's Fetcher fetched may be larger than
			// this one's would.
			if m.size > limit {
				return fmt.Errorf("statuslist: fetch %s: token exceeds %d bytes", ref.URI, limit)
			}
			if err := recheck(m); err != nil {
				return err
			}
			used = m
			return nil
		})
	if err != nil {
		return 0, TokenClaims{}, err
	}
	// Read once the token passed, so that a reference the list doesn't
	// cover, say, doesn't keep the list from being cached.
	status, parsed, err := checkClaims(used.parsed, ref, used.decoded)
	if err != nil {
		return 0, TokenClaims{}, err
	}
	return status, parsed.claims.clone(), nil
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
