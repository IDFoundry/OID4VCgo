// Package listhttp serves the tokens statuslist's and identifierlist's
// Publishers sign: a Cache that signs a token once for many requests,
// and Write, which answers a request with one.
package listhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"strconv"
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

	gzipOnce sync.Once
	gzipped  []byte // Bytes, gzip-compressed once first asked for
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
	mu       sync.Mutex
	token    *Token
	building *build
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
	signCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), SignTimeout)
	defer cancel()
	if window <= 0 {
		// Nothing shared: a token per call.
		now := clock()
		token, err := signToken(signCtx, now, sign)
		return Served{Token: token, Now: now}, err
	}
	c.mu.Lock()
	now := clock()
	if t := c.token; t != nil && now.Sub(t.SignedAt) < window && !now.Before(t.SignedAt) {
		c.mu.Unlock()
		return Served{Token: t, Now: now}, nil
	}
	b := c.building
	if b == nil {
		b = &build{done: make(chan struct{}), err: errors.New("listhttp: signing the token panicked")}
		c.building = b
		c.mu.Unlock()
		c.run(signCtx, b, now, sign)
	} else {
		c.mu.Unlock()
		<-b.done
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now = clock()
	if b.err == nil {
		return Served{Token: b.token, Now: now}, nil
	}
	if t := c.token; t != nil && !now.Before(t.SignedAt) && now.Before(t.Exp) {
		return Served{Token: t, Now: now}, b.err
	}
	return Served{}, b.err
}

// run signs b's token, caches it unless Invalidate dropped b, and
// closes b.done, even if sign panics.
func (c *Cache) run(ctx context.Context, b *build, now time.Time, sign SignFunc) {
	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.building == b {
			c.building = nil
			if b.err == nil {
				c.token = b.token
			}
		}
		close(b.done)
	}()
	b.token, b.err = signToken(ctx, now, sign)
}

func signToken(ctx context.Context, now time.Time, sign SignFunc) (*Token, error) {
	token, exp, err := sign(ctx, now)
	if err != nil {
		return nil, err
	}
	return &Token{Bytes: token, SignedAt: now, Exp: exp}, nil
}

// Invalidate drops the cached token, and any signature under way, so
// the next call signs a new one. Until one is signed, Get has no token
// to fall back on.
func (c *Cache) Invalidate() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token, c.building = nil, nil
}

// Write answers r with served's token, as contentType, gzip-compressed
// when gz is set. When ttl is positive, Cache-Control's max-age is the
// ttl left since the token was signed, no later than its exp, in whole
// seconds. It writes nothing when it fails.
func Write(w http.ResponseWriter, r *http.Request, served Served, contentType string, ttl time.Duration, gz bool) error {
	body := served.Bytes
	if gz {
		served.gzipOnce.Do(func() {
			served.gzipped, served.gzipErr = gzipBytes(served.Bytes)
		})
		if served.gzipErr != nil {
			return served.gzipErr
		}
		body = served.gzipped
	}
	h := w.Header()
	if ttl > 0 {
		// To the nearest second: a token signed for this request has
		// all its ttl left, not a second less.
		maxAge := max(min(ttl-served.Now.Sub(served.SignedAt), served.Exp.Sub(served.Now)), 0).Round(time.Second)
		h.Set("Cache-Control", "max-age="+strconv.FormatInt(int64(maxAge/time.Second), 10))
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
