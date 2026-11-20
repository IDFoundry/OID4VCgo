package statuscache

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A fetch that panics fails its checks with an error, rather than end
// the process from the flight's goroutine.
func TestCheck_FetchPanicFails(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	fetch := func(context.Context) ([]byte, error) { panic("a wrapped transport") }
	var n counter
	err := c.Check(context.Background(), "u", "m", "", plain(fetch), n.verify(Verified{Iat: now.Unix()}, nil), n.rechecks(nil))
	if err == nil || !strings.Contains(err.Error(), "panicked") {
		t.Fatalf("Check whose fetch panics = %v, want an error saying so", err)
	}
	n.want(t, 0, 0, "a fetch that panicked")
}

// A Verify that panics, for one of two checks sharing a fetch, reaches
// its own caller, and passes the turn on: the other check verifies the
// token itself, rather than wait for a turn never given back.
func TestCheck_VerifyPanicPassesTurn(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	c := New(Options{Now: func() time.Time { return now }})
	gate := make(chan struct{})
	fetch := func(context.Context) ([]byte, error) { <-gate; return []byte("token"), nil }
	var panicked atomic.Bool
	verify := func([]byte) (Verified, error) {
		if panicked.CompareAndSwap(false, true) {
			panic("a verifier's bug")
		}
		return Verified{Iat: now.Unix(), Memo: "memo"}, nil
	}
	recheck := func(any) error { return nil }
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results := make(chan any, 2)
	var joined atomic.Int32
	for range 2 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					results <- r
				}
			}()
			joined.Add(1)
			results <- c.Check(ctx, "u", "m", "", plain(fetch), verify, recheck)
		}()
	}
	for joined.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond) // let both join the fetch
	close(gate)
	panics := 0
	for range 2 {
		switch r := (<-results).(type) {
		case nil:
		case error:
			t.Errorf("the check sharing the fetch = %v, want it to verify the token", r)
		default:
			panics++
		}
	}
	if panics != 1 {
		t.Errorf("%d checks panicked, want 1: the panic reaches its caller", panics)
	}
}
