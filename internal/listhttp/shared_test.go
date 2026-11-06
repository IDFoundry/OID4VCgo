package listhttp

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore is a Store holding one token, whose every method can be
// made to fail, and whose Token can be made to return something other
// than what Head describes.
type fakeStore struct {
	mu                                  sync.Mutex
	version                             int64
	token                               *Stored
	leased                              bool
	headErr, tokenErr, claimErr, putErr error
	tokenOverride                       *Stored // Token returns this (or nothing, if Bytes is nil)
	puts                                int
}

func (s *fakeStore) Head(context.Context) (Head, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.headErr != nil {
		return Head{}, s.headErr
	}
	h := Head{Version: s.version}
	if s.token != nil {
		h.Stored, h.Token = true, *s.token
		h.Token.Bytes = nil
	}
	return h, nil
}

func (s *fakeStore) Token(context.Context) (Stored, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.tokenErr != nil:
		return Stored{}, false, s.tokenErr
	case s.tokenOverride != nil:
		return *s.tokenOverride, s.tokenOverride.Bytes != nil, nil
	case s.token == nil:
		return Stored{}, false, nil
	}
	return *s.token, true, nil
}

func (s *fakeStore) Claim(context.Context, string, time.Time, time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.claimErr != nil {
		return false, s.claimErr
	}
	return !s.leased, nil
}

func (s *fakeStore) Put(_ context.Context, _ string, token Stored) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	if s.putErr != nil {
		return s.putErr
	}
	s.token = &token
	return nil
}

// sharedFixture is a Cache sharing through a fakeStore on a clock it
// controls, signing "signed-N" tokens, failing while signErr is set.
type sharedFixture struct {
	t       *testing.T
	cache   Cache
	store   *fakeStore
	now     time.Time
	signs   int
	signErr error
}

func newSharedFixture(t *testing.T) *sharedFixture {
	return &sharedFixture{t: t, store: &fakeStore{}, now: time.UnixMilli(time.Now().UnixMilli())}
}

func (f *sharedFixture) get(fresh time.Duration) (Served, error) {
	sh := Shared{Store: f.store, Holder: "me", Fresh: fresh, Check: time.Second}
	return f.cache.GetShared(context.Background(), sh, func() time.Time { return f.now }, func(_ context.Context, now time.Time) ([]byte, time.Time, error) {
		if f.signErr != nil {
			return nil, time.Time{}, f.signErr
		}
		f.signs++
		return []byte("signed-" + strconv.Itoa(f.signs)), now.Add(time.Hour), nil
	})
}

// storeToken puts a token signed at signedAt, from the store's version,
// in the store.
func (f *sharedFixture) storeToken(b string, signedAt time.Time) {
	f.store.token = &Stored{Bytes: []byte(b), Version: f.store.version, SignedAt: signedAt, Exp: signedAt.Add(time.Hour)}
}

// With Fresh not positive, every call signs, and the Store isn't used.
func TestGetShared_NoWindowSignsPerCall(t *testing.T) {
	f := newSharedFixture(t)
	f.store.headErr = errors.New("not to be read")
	for range 2 {
		if served, err := f.get(0); err != nil || served.Token == nil {
			t.Fatalf("GetShared: %v", err)
		}
	}
	if f.signs != 2 {
		t.Fatalf("%d signatures, want 2", f.signs)
	}
}

// A failure to take the lease, or to sign once it's taken, serves
// nothing new: the cached token while it's unexpired, otherwise none.
func TestGetShared_ClaimAndSignErrors(t *testing.T) {
	for name, fail := range map[string]func(*sharedFixture, error){
		"claim": func(f *sharedFixture, err error) { f.store.claimErr = err },
		"sign":  func(f *sharedFixture, err error) { f.signErr = err },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSharedFixture(t)
			down := errors.New(name + " failed")
			fail(f, down)
			if served, err := f.get(time.Minute); !errors.Is(err, down) || served.Token != nil {
				t.Fatalf("no token yet: %v, %v; want the error and nothing served", served.Token, err)
			}
			fail(f, nil)
			first, err := f.get(time.Minute)
			if err != nil || first.Token == nil {
				t.Fatalf("recovered: %v", err)
			}
			fail(f, down)
			f.now = f.now.Add(2 * time.Minute)
			if served, err := f.get(time.Minute); !errors.Is(err, down) || served.Token != first.Token {
				t.Fatalf("failing with a cached token: %v; want the cached token and the error", err)
			}
		})
	}
}

// A token the Store won't take is served all the same, with the error.
func TestGetShared_PutErrorStillServes(t *testing.T) {
	f := newSharedFixture(t)
	f.store.putErr = errors.New("store full")
	served, err := f.get(time.Minute)
	if !errors.Is(err, f.store.putErr) || served.Token == nil || string(served.Bytes) != "signed-1" {
		t.Fatalf("GetShared = %v, %v; want the new token and the error", served.Token, err)
	}
}

// Invalidate has the next call sign, even with a current token stored;
// when that call fails before signing, the one after still signs.
func TestGetShared_InvalidateForcesSigning(t *testing.T) {
	f := newSharedFixture(t)
	f.storeToken("stored", f.now)
	if served, err := f.get(time.Minute); err != nil || string(served.Bytes) != "stored" {
		t.Fatalf("current token stored: %v; want it served", err)
	}
	f.cache.Invalidate()
	f.store.claimErr = errors.New("lease unavailable")
	if _, err := f.get(time.Minute); !errors.Is(err, f.store.claimErr) {
		t.Fatalf("after Invalidate, Claim failing: %v", err)
	}
	f.store.claimErr = nil
	f.store.leased = true // another replica's lease: signed here anyway
	served, err := f.get(time.Minute)
	if err != nil || string(served.Bytes) != "signed-1" {
		t.Fatalf("after Invalidate: %q, %v; want a token signed here", served.Bytes, err)
	}
}

// A stored token that can't be read, is gone, or has expired since
// Head described it is served by nobody.
func TestGetShared_StoredTokenUnreadable(t *testing.T) {
	for name, c := range map[string]struct {
		set  func(*fakeStore, time.Time)
		want string
	}{
		"read error": {func(s *fakeStore, _ time.Time) { s.tokenErr = errors.New("read failed") }, "read failed"},
		"gone":       {func(s *fakeStore, _ time.Time) { s.tokenOverride = &Stored{} }, "gone"},
		"expired": {func(s *fakeStore, now time.Time) {
			s.tokenOverride = &Stored{Bytes: []byte("old"), SignedAt: now.Add(-2 * time.Hour), Exp: now}
		}, "expired"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSharedFixture(t)
			f.storeToken("stored", f.now)
			c.set(f.store, f.now)
			served, err := f.get(time.Minute)
			if err == nil || served.Token != nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("GetShared = %v, %v; want nothing served and an error naming %q", served.Token, err, c.want)
			}
			if f.signs != 0 {
				t.Fatalf("%d signatures, want none: the stored token is current", f.signs)
			}
		})
	}
}

// While another replica holds the lease, a stale stored token is
// served, not signed here, and the same token again from the next
// check; a Head that fails serves nothing new.
func TestGetShared_LeasedAndHeadError(t *testing.T) {
	f := newSharedFixture(t)
	f.storeToken("stored", f.now.Add(-2*time.Minute))
	f.store.leased = true
	first, err := f.get(time.Minute)
	if err != nil || string(first.Bytes) != "stored" || f.signs != 0 {
		t.Fatalf("leased elsewhere: %q, %v, %d signatures; want the stored token", first.Bytes, err, f.signs)
	}
	f.now = f.now.Add(2 * time.Second)
	if again, err := f.get(time.Minute); err != nil || again.Token != first.Token {
		t.Fatalf("next check: %v; want the same token", err)
	}
	f.store.headErr = errors.New("head failed")
	f.now = f.now.Add(2 * time.Second)
	if served, err := f.get(time.Minute); !errors.Is(err, f.store.headErr) || served.Token != first.Token {
		t.Fatalf("Head failing: %v; want the cached token and the error", err)
	}
}
