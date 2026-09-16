package main

import (
	"sync"
	"time"

	"github.com/idfoundry/fapigo/server"
)

// pendingSet is a thread-safe, TTL-evicting, single-use map bridging
// GET /authorize (Put) to POST /authorize/decision (TakeOnce) — the
// same shape FAPIgo's own cmd/conformance-as/pending.go establishes;
// this binary needs its own copy since cmd/ packages can't import one
// another's package main.
type pendingSet[K comparable, V any] struct {
	mu    sync.Mutex
	clock server.Clock
	items map[K]pendingEntry[V]
}

type pendingEntry[V any] struct {
	value     V
	expiresAt time.Time
}

func newPendingSet[K comparable, V any](clock server.Clock) *pendingSet[K, V] {
	return &pendingSet[K, V]{clock: clock, items: make(map[K]pendingEntry[V])}
}

// Put stashes value under key, expiring after ttl if TakeOnce is never
// called for it. Also sweeps every already-expired entry first.
func (s *pendingSet[K, V]) Put(key K, value V, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	for k, entry := range s.items {
		if !now.Before(entry.expiresAt) {
			delete(s.items, k)
		}
	}
	s.items[key] = pendingEntry[V]{value: value, expiresAt: now.Add(ttl)}
}

// TakeOnce retrieves and retires the entry stashed under key — a
// second call with the same key, or a call after its own ttl expired,
// always misses.
func (s *pendingSet[K, V]) TakeOnce(key K) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.items[key]
	if ok {
		delete(s.items, key)
	}
	if !ok || s.clock.Now().After(entry.expiresAt) {
		var zero V
		return zero, false
	}
	return entry.value, true
}
