package listhttp

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestCache_SharesOneSignature: concurrent calls wait on one signature,
// made with a context the caller's cancellation doesn't end, and get
// its token.
func TestCache_SharesOneSignature(t *testing.T) {
	var c Cache
	now := time.Now()
	clock := func() time.Time { return now }
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	sign := func(ctx context.Context, now time.Time) ([]byte, time.Time, error) {
		if calls.Add(1) == 1 {
			close(entered)
		}
		<-release
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return []byte("token"), now.Add(time.Hour), nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var wg sync.WaitGroup
	results := make([]Served, 8)
	errs := make([]error, len(results))
	get := func(i int) {
		defer wg.Done()
		results[i], errs[i] = c.Get(ctx, time.Minute, clock, sign)
	}
	wg.Add(1)
	go get(0)
	<-entered
	wg.Add(len(results) - 1)
	for i := 1; i < len(results); i++ {
		go get(i)
	}
	time.Sleep(20 * time.Millisecond) // let them reach the wait
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Errorf("%d signatures, want 1", n)
	}
	for i, served := range results {
		if errs[i] != nil || served.Token != results[0].Token {
			t.Errorf("call %d: %v, %v; want the shared token", i, served.Token, errs[i])
		}
	}
}

// TestCache_ServesStaleOnError: a failed signature falls back on the
// cached token while it's unexpired, with the error, and not once it
// has expired or been invalidated; a panicking signature releases the
// calls waiting on it.
func TestCache_ServesStaleOnError(t *testing.T) {
	var c Cache
	now := time.Now()
	clock := func() time.Time { return now }
	var failWith error
	sign := func(_ context.Context, now time.Time) ([]byte, time.Time, error) {
		if failWith != nil {
			return nil, time.Time{}, failWith
		}
		return []byte(now.String()), now.Add(time.Hour), nil
	}
	first, err := c.Get(context.Background(), time.Minute, clock, sign)
	if err != nil {
		t.Fatal(err)
	}
	dbDown := errors.New("db down")
	failWith = dbDown
	now = now.Add(30 * time.Minute)
	if served, err := c.Get(context.Background(), time.Minute, clock, sign); !errors.Is(err, dbDown) || served.Token != first.Token {
		t.Errorf("unexpired: %v, %v; want the cached token and the error", served.Token, err)
	}
	now = now.Add(30 * time.Minute)
	if served, err := c.Get(context.Background(), time.Minute, clock, sign); !errors.Is(err, dbDown) || served.Token != nil {
		t.Errorf("expired: %v, %v; want no token and the error", served.Token, err)
	}

	failWith = nil
	now = now.Add(time.Minute)
	if _, err := c.Get(context.Background(), time.Minute, clock, sign); err != nil {
		t.Fatal(err)
	}
	c.Invalidate()
	failWith = dbDown
	if served, err := c.Get(context.Background(), time.Minute, clock, sign); !errors.Is(err, dbDown) || served.Token != nil {
		t.Errorf("invalidated: %v, %v; want no token and the error", served.Token, err)
	}

	func() {
		defer func() { _ = recover() }()
		_, _ = c.Get(context.Background(), time.Minute, clock, func(context.Context, time.Time) ([]byte, time.Time, error) { panic("boom") })
	}()
	failWith = nil
	if served, err := c.Get(context.Background(), time.Minute, clock, sign); err != nil || served.Token == nil {
		t.Errorf("after a panic: %v, %v; want a new token", served.Token, err)
	}
}

// TestCache_InvalidateDuringSigning: a signature under way when
// Invalidate is called isn't cached, so the next call signs again.
func TestCache_InvalidateDuringSigning(t *testing.T) {
	var c Cache
	now := time.Now()
	clock := func() time.Time { return now }
	calls := 0
	sign := func(_ context.Context, now time.Time) ([]byte, time.Time, error) {
		calls++
		if calls == 1 {
			c.Invalidate()
		}
		return []byte("token"), now.Add(time.Hour), nil
	}
	for range 2 {
		if _, err := c.Get(context.Background(), time.Minute, clock, sign); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Errorf("%d signatures, want 2", calls)
	}
}

// TestWrite: a response's Cache-Control max-age counts down the ttl
// left, to the nearest second, and no later than the token's exp; and
// a gzip-compressed body decodes to the token.
func TestWrite(t *testing.T) {
	signedAt := time.Now()
	token := &Token{Bytes: []byte("token"), SignedAt: signedAt, Exp: signedAt.Add(90 * time.Second)}
	write := func(token *Token, at time.Duration, gz bool) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		if err := Write(rec, httptest.NewRequest(http.MethodGet, "/l", nil), Served{Token: token, Now: signedAt.Add(at)}, "application/x", time.Minute, gz); err != nil {
			t.Fatal(err)
		}
		return rec
	}
	for at, want := range map[time.Duration]string{
		0:                      "max-age=60",
		20 * time.Second:       "max-age=40",
		40*time.Second + 400e6: "max-age=20",
		59*time.Second + 999e6: "max-age=0",
		70 * time.Second:       "max-age=0", // past the ttl, before exp
		100 * time.Second:      "max-age=0", // past exp
	} {
		if got := write(token, at, false).Header().Get("Cache-Control"); got != want {
			t.Errorf("served %v after signing: Cache-Control %q, want %q", at, got, want)
		}
	}
	shortLived := &Token{Bytes: token.Bytes, SignedAt: signedAt, Exp: signedAt.Add(30 * time.Second)}
	if got := write(shortLived, 0, false).Header().Get("Cache-Control"); got != "max-age=30" {
		t.Errorf("exp before the ttl ends: Cache-Control %q, want max-age=30", got)
	}

	plain := write(token, 0, false)
	if plain.Code != http.StatusOK || plain.Body.String() != "token" || plain.Header().Get("Content-Type") != "application/x" {
		t.Fatalf("200: %d %q, headers %v", plain.Code, plain.Body, plain.Header())
	}
	zipped := write(token, 0, true)
	zr, err := gzip.NewReader(zipped.Body)
	if err != nil {
		t.Fatal(err)
	}
	if body, err := io.ReadAll(zr); err != nil || !bytes.Equal(body, token.Bytes) || zipped.Header().Get("Content-Encoding") != "gzip" {
		t.Errorf("gzip: %q, %v, headers %v", body, err, zipped.Header())
	}

	rec := httptest.NewRecorder()
	if err := Write(rec, httptest.NewRequest(http.MethodGet, "/l", nil), Served{Token: token, Now: signedAt}, "application/x", 0, false); err != nil || rec.Header().Get("Cache-Control") != "" {
		t.Errorf("no ttl: Cache-Control %q, %v; want none", rec.Header().Get("Cache-Control"), err)
	}
}
