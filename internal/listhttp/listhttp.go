// Package listhttp serves the tokens statuslist's and identifierlist's
// Publishers sign: a Cache that signs a token once for many requests,
// or shares one signed by any of the replicas serving the list through
// a Store, and Write, which answers a request with one.
package listhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SignTimeout bounds a signature a Cache makes, which doesn't end with
// the request that started it.
const SignTimeout = 30 * time.Second

// SignFunc signs a token issued at now, and returns its exp.
type SignFunc func(ctx context.Context, now time.Time) (token []byte, exp time.Time, err error)

// Token is a signed token, when it was signed, and when it expires.
type Token struct {
	Bytes         []byte
	SignedAt, Exp time.Time

	version  int64 // the list version it was signed from, when shared
	etag     string
	gzipOnce sync.Once
	gzipped  []byte // Bytes, gzip-compressed once first asked for
	gzipETag string
	gzipErr  error
}

// Served is a Token and the time it's served at.
type Served struct {
	*Token
	Now time.Time
}

// Cache holds the token a Publisher serves. Its zero value is empty;
// a Cache must not be copied after first use.
type Cache struct {
	mu        sync.Mutex
	token     *Token
	checkedAt time.Time // when token was signed, or last found current in a Store
	building  *build
	forced    bool // Invalidate was called: GetShared signs, whatever the Store holds
}

// build is a signature under way: done is closed once token or err is
// set.
type build struct {
	done  chan struct{}
	token *Token
	err   error
}

// Get returns the cached token, signing a new one once it's older than
// window, and for every call when window isn't positive. Concurrent
// calls share one signature, made with a context that doesn't end with
// ctx, bounded by SignTimeout. When signing fails and the cached token
// hasn't expired, it's returned with the error; otherwise Served's
// Token is nil.
func (c *Cache) Get(ctx context.Context, window time.Duration, clock func() time.Time, sign SignFunc) (Served, error) {
	return c.get(ctx, window, clock, func(ctx context.Context, now time.Time, _ *Token) (*Token, error) {
		return signToken(ctx, now, sign)
	})
}

// produceFunc makes the token a Cache serves from now on, given the one
// it serves now (nil if none). A token returned with an error is served,
// and the error reported.
type produceFunc func(ctx context.Context, now time.Time, prev *Token) (*Token, error)

// get is Get, with produce making each new token, at most once every
// window.
func (c *Cache) get(ctx context.Context, window time.Duration, clock func() time.Time, produce produceFunc) (Served, error) {
	signCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), SignTimeout)
	defer cancel()
	if window <= 0 {
		// Nothing shared: a token per call.
		now := clock()
		token, err := produce(signCtx, now, nil)
		return Served{Token: token, Now: now}, err
	}
	c.mu.Lock()
	now := clock()
	if t := c.token; t != nil && now.Sub(c.checkedAt) < window && !now.Before(c.checkedAt) {
		c.mu.Unlock()
		return Served{Token: t, Now: now}, nil
	}
	b := c.building
	if b == nil {
		b = &build{done: make(chan struct{}), err: errors.New("listhttp: signing the token panicked")}
		c.building = b
		prev := c.token
		c.mu.Unlock()
		c.run(signCtx, b, now, prev, produce)
	} else {
		c.mu.Unlock()
		<-b.done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now = clock()
	if b.token != nil {
		return Served{Token: b.token, Now: now}, b.err
	}
	if t := c.token; t != nil && !now.Before(c.checkedAt) && now.Before(t.Exp) {
		return Served{Token: t, Now: now}, b.err
	}
	return Served{}, b.err
}

// run makes b's token, caches it unless Invalidate dropped b, and
// closes b.done, even if produce panics.
func (c *Cache) run(ctx context.Context, b *build, now time.Time, prev *Token, produce produceFunc) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.building == b {
			c.building = nil
			if b.token != nil {
				c.token, c.checkedAt = b.token, now
			}
		}
		close(b.done)
	}()
	b.token, b.err = produce(ctx, now, prev)
}

func signToken(ctx context.Context, now time.Time, sign SignFunc) (*Token, error) {
	token, exp, err := sign(ctx, now)
	if err != nil {
		return nil, err
	}
	return &Token{Bytes: token, SignedAt: now, Exp: exp, etag: etag(token)}, nil
}

// Invalidate drops the cached token, and any signature under way, so
// the next call signs a new one — with GetShared, whatever the Store
// holds. Until one is signed, Get has no token to fall back on.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.building, c.forced = nil, nil, true
}

// Write answers r with served's token, as contentType, gzip-compressed
// when gz is set. It carries a strong ETag, a hash of the bytes sent,
// and answers 304 Not Modified to an If-None-Match that names it. When
// ttl is positive, Cache-Control's max-age is the ttl left since the
// token was signed, no later than its exp, in whole seconds. It writes
// nothing when it fails.
func Write(w http.ResponseWriter, r *http.Request, served Served, contentType string, ttl time.Duration, gz bool) error {
	body, tag := served.Bytes, served.etag
	if gz {
		served.gzipOnce.Do(func() {
			served.gzipped, served.gzipErr = gzipBytes(served.Bytes)
			served.gzipETag = etag(served.gzipped)
		})
		if served.gzipErr != nil {
			return served.gzipErr
		}
		body, tag = served.gzipped, served.gzipETag
	}
	h := w.Header()
	h.Set("ETag", tag)
	if ttl > 0 {
		// To the nearest second: a token signed for this request has
		// all its ttl left, not a second less.
		// A token another replica signed may carry a SignedAt a little
		// ahead of this one's clock: it's no younger than new.
		age := max(served.Now.Sub(served.SignedAt), 0)
		maxAge := max(min(ttl-age, served.Exp.Sub(served.Now)), 0).Round(time.Second)
		h.Set("Cache-Control", "public, max-age="+strconv.FormatInt(int64(maxAge/time.Second), 10))
	}
	if matches(r.Header.Values("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return nil
	}
	if gz {
		h.Set("Content-Encoding", "gzip")
	}
	h.Set("Content-Type", contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	// #nosec G705 -- body is a token a Publisher signed, sent as its own
	// media type with nosniff, never HTML.
	_, _ = w.Write(body)
	return nil
}

// etag is a strong entity tag for b: its SHA-256, base64url-encoded.
func etag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:]) + `"`
}

// matches reports whether If-None-Match header lines name tag, or are
// "*", by weak comparison (RFC 9110 §13.1.2).
func matches(ifNoneMatch []string, tag string) bool {
	for _, line := range ifNoneMatch {
		for _, candidate := range strings.Split(line, ",") {
			candidate = strings.TrimPrefix(strings.TrimSpace(candidate), "W/")
			if candidate == "*" || candidate == tag {
				return true
			}
		}
	}
	return false
}

func gzipBytes(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
