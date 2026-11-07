package statuscache

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func ptr(v int64) *int64 { return &v }

func TestExpiry(t *testing.T) {
	at := time.Unix(1_000_000, 0)
	c := New(Options{MaxAge: time.Hour})
	for name, tc := range map[string]struct {
		v    Verified
		want time.Time
	}{
		"MaxAge alone":    {Verified{Iat: at.Unix()}, at.Add(time.Hour)},
		"exp first":       {Verified{Iat: at.Unix(), Exp: ptr(at.Unix() + 60)}, at.Add(time.Minute)},
		"ttl first":       {Verified{Iat: at.Unix() - 30, TTL: ptr(60), Exp: ptr(at.Unix() + 600)}, at.Add(30 * time.Second)},
		"ttl overflowing": {Verified{Iat: at.Unix(), TTL: ptr(math.MaxInt64)}, at.Add(time.Hour)},
	} {
		if got := c.expiry(tc.v, at, nil); !got.Equal(tc.want) {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}

// A token already expired when its fetch finished isn't stored, and a
// failed verification returns its error.
func TestCheck_NotStored(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	fetch := func(context.Context) ([]byte, error) { return []byte("token"), nil }
	expired := func([]byte) (Verified, error) { return Verified{Iat: now.Unix() - 120, TTL: ptr(60)}, nil }
	if err := c.Check(context.Background(), "u", "m", "", plain(fetch), expired, nil); err != nil {
		t.Fatal(err)
	}
	if n, _ := c.Len(); n != 0 {
		t.Errorf("an expired token was stored")
	}
	refused := errors.New("refused")
	if err := c.Check(context.Background(), "u", "m", "", plain(fetch), func([]byte) (Verified, error) { return Verified{}, refused }, nil); !errors.Is(err, refused) {
		t.Errorf("Check = %v, want the verification's error", err)
	}
	if n, _ := c.Len(); n != 0 {
		t.Errorf("a refused token was stored")
	}
}

// counter counts a check's calls to its Verify and Recheck.
type counter struct {
	mu                sync.Mutex
	verifies, recheck int
}

func (n *counter) verify(v Verified, err error) Verify {
	return func([]byte) (Verified, error) {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.verifies++
		return v, err
	}
}

func (n *counter) rechecks(err error) Recheck {
	return func(any) error {
		n.mu.Lock()
		defer n.mu.Unlock()
		n.recheck++
		return err
	}
}

func (n *counter) want(t *testing.T, verifies, rechecks int, when string) {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.verifies != verifies || n.recheck != rechecks {
		t.Errorf("%s: %d verifications and %d rechecks, want %d and %d", when, n.verifies, n.recheck, verifies, rechecks)
	}
}

// A hit is rechecked, not verified, and a hit its recheck refuses is
// fetched and verified afresh.
func TestCheck_HitRechecked(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	var fetches atomic.Int32
	fetch := func(context.Context) ([]byte, error) { fetches.Add(1); return []byte("token"), nil }
	ctx := context.Background()
	var n counter
	v := Verified{Iat: now.Unix(), Memo: "memo", MemoBytes: 4}
	for range 3 {
		if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(v, nil), n.rechecks(nil)); err != nil {
			t.Fatal(err)
		}
	}
	n.want(t, 1, 2, "three checks")
	refused := errors.New("refused")
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(v, nil), n.rechecks(refused)); err != nil {
		t.Errorf("a refused hit, verified afresh: %v", err)
	}
	n.want(t, 2, 3, "a refused hit")
	if got := fetches.Load(); got != 2 {
		t.Errorf("%d fetches, want 2", got)
	}
}

// Concurrent misses share one fetch, which the first of them verifies
// and the others recheck; a caller whose verification fails leaves the
// next to verify it itself.
func TestCheck_Stampede(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	for name, refusing := range map[string]bool{"all pass": false, "one refuses": true} {
		c := New(Options{Now: func() time.Time { return now }})
		gate := make(chan struct{})
		var fetches, joined, failed atomic.Int32
		fetch := func(context.Context) ([]byte, error) { fetches.Add(1); <-gate; return []byte("token"), nil }
		var n counter
		v := Verified{Iat: now.Unix(), Memo: "memo"}
		const callers = 16
		var wg sync.WaitGroup
		for i := range callers {
			verify, recheck := n.verify(v, nil), n.rechecks(nil)
			if refusing && i == 0 {
				refused := errors.New("refused")
				verify, recheck = n.verify(Verified{}, refused), n.rechecks(refused)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				joined.Add(1)
				if err := c.Check(context.Background(), "u", "m", "", plain(fetch), verify, recheck); err != nil {
					failed.Add(1)
				}
			}()
		}
		for joined.Load() < callers {
			time.Sleep(time.Millisecond)
		}
		time.Sleep(20 * time.Millisecond) // let the last join the fetch
		close(gate)
		wg.Wait()
		if got := fetches.Load(); got != 1 {
			t.Errorf("%s: %d fetches, want 1", name, got)
		}
		n.mu.Lock()
		// Verified once, or twice when the refusing caller went first.
		if most := 1 + int(failed.Load()); n.verifies < 1 || n.verifies > most || n.verifies+n.recheck != callers {
			t.Errorf("%s: %d verifications and %d rechecks", name, n.verifies, n.recheck)
		}
		n.mu.Unlock()
		if got, want := failed.Load(), map[bool]int32{false: 0, true: 1}[refusing]; got != want {
			t.Errorf("%s: %d checks failed, want %d", name, got, want)
		}
	}
}

// A failed fetch fails every check with its policy for MaxFailureAge,
// then is fetched again; another policy fetches on its own.
func TestCheck_FetchFailureKept(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{MaxFailureAge: 10 * time.Second, Now: func() time.Time { return now }})
	down := errors.New("down")
	var fetches atomic.Int32
	failing := true
	fetch := func(context.Context) ([]byte, error) {
		fetches.Add(1)
		if failing {
			return nil, down
		}
		return []byte("token"), nil
	}
	var n counter
	v := Verified{Iat: now.Unix(), Memo: "memo"}
	ctx := context.Background()
	for range 2 {
		if err := c.Check(ctx, "u", "m", "p", plain(fetch), n.verify(v, nil), n.rechecks(nil)); !errors.Is(err, down) {
			t.Errorf("Check = %v, want the fetch's error", err)
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("%d fetches, want 1", got)
	}
	failing = false
	if err := c.Check(ctx, "u", "m", "other", plain(fetch), n.verify(v, nil), n.rechecks(nil)); err != nil {
		t.Errorf("another policy: %v", err)
	}
	now = now.Add(10 * time.Second)
	if err := c.Check(ctx, "u", "m", "p", plain(fetch), n.verify(v, nil), n.rechecks(nil)); err != nil {
		t.Errorf("after MaxFailureAge: %v", err)
	}
	if got := fetches.Load(); got != 2 {
		t.Errorf("%d fetches, want 2", got)
	}
}

// Bytes a check refused are kept for MaxFailureAge and verified again
// rather than fetched, unless they're the verified entry's, whose
// recheck's error then stands; and they're not used past what their
// ttl allows.
func TestCheck_RefusedTokenKept(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	var fetches atomic.Int32
	fetch := func(context.Context) ([]byte, error) { fetches.Add(1); return []byte("token"), nil }
	refused := errors.New("refused")
	ctx := context.Background()
	var n counter
	v := Verified{Iat: now.Unix(), Memo: "memo", MemoBytes: 4}
	for range 2 {
		if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(Verified{}, refused), n.rechecks(nil)); !errors.Is(err, refused) {
			t.Fatalf("Check = %v", err)
		}
	}
	n.want(t, 2, 0, "a refused token, checked twice")
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(v, nil), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("%d fetches, want 1", got)
	}
	if entries, _ := c.Len(); entries != 1 {
		t.Errorf("the kept token, once verified: %d entries, want 1", entries)
	}
	// The entry's own bytes, refetched and refused: its recheck stands.
	now = now.Add(time.Second)
	c.Purge()
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(v, nil), n.rechecks(nil)); err != nil {
		t.Fatal(err)
	}
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(Verified{}, refused), n.rechecks(refused)); !errors.Is(err, refused) {
		t.Fatalf("Check = %v", err)
	}
	before := fetches.Load()
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(Verified{}, refused), n.rechecks(refused)); !errors.Is(err, refused) {
		t.Errorf("Check = %v, want the recheck's error", err)
	}
	if fetches.Load() != before {
		t.Errorf("the entry's refused bytes were fetched again")
	}

	// Kept bytes whose ttl has passed are fetched afresh.
	c.Purge()
	short := Verified{Iat: now.Unix(), TTL: ptr(5), Memo: "memo"}
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(Verified{}, refused), nil); !errors.Is(err, refused) {
		t.Fatal(err)
	}
	now = now.Add(5 * time.Second)
	before = fetches.Load()
	if err := c.Check(ctx, "u", "m", "", plain(fetch), n.verify(short, nil), nil); err != nil {
		t.Fatal(err)
	}
	if fetches.Load() != before+1 {
		t.Errorf("kept bytes past their ttl weren't fetched afresh")
	}
}

// The memos and failures held stay within MaxEntries and MaxBytes, the
// least recently used dropped first, and a memo larger than MaxBytes
// isn't kept.
func TestCheck_Bounds(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{MaxEntries: 3, MaxBytes: 100, Now: func() time.Time { return now }})
	fetch := func(context.Context) ([]byte, error) { return []byte("token"), nil }
	ctx := context.Background()
	check := func(uri string, size int) {
		t.Helper()
		v := Verified{Iat: now.Unix(), Memo: uri, MemoBytes: size}
		if err := c.Check(ctx, uri, "m", "", plain(fetch), func([]byte) (Verified, error) { return v, nil }, func(any) error { return nil }); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 10 {
		check(string(rune('a'+i)), 40)
		if n, size := c.Len(); n > 2 || size > 100 {
			t.Fatalf("%d entries, %d bytes, over MaxBytes", n, size)
		}
	}
	check("big", 101)
	if n, size := c.Len(); n != 2 || size != 80 {
		t.Errorf("after a memo over MaxBytes: %d entries, %d bytes", n, size)
	}
	for i := range 10 {
		check(string(rune('k'+i)), 1)
	}
	if n, size := c.Len(); n != 3 || size != 3 {
		t.Errorf("%d entries, %d bytes, want MaxEntries", n, size)
	}
}

// plain is fetch as a Fetch that never revalidates: what a server
// without validators answers.
func plain(fetch func(context.Context) ([]byte, error)) Fetch {
	return func(ctx context.Context, _ Validators) (Fetched, error) {
		token, err := fetch(ctx)
		return Fetched{Token: token}, err
	}
}
