package walletprovider

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// The challenge endpoint's limit for each client address: a burst of
// challengeBurst, then challengeRate a second. One address can then
// hold at most challengeBurst + challengeRate × ChallengeLifetime (320)
// challenges outstanding, so it takes some 30 addresses, not one, to
// fill maxOutstandingChallenges and lock every Android device out.
const (
	challengeRate  = 1.0
	challengeBurst = 20.0
	// maxLimitedClients bounds the addresses tracked; past it, those
	// whose buckets have refilled are forgotten, and if none has, a new
	// address waits.
	maxLimitedClients = 4096
)

// clientAddress is the address a request came from: its connection's
// remote IP. It trusts no forwarded-address header, as nothing else in
// the demo does, so behind a tunnel (cloudflared on this machine) every
// client shares the tunnel's address and the limit applies to them all
// together — which still keeps one client from filling the challenge
// table, but lets one slow the others.
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientLimiter is a token bucket for each client address.
type clientLimiter struct {
	rate, burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newClientLimiter(rate, burst float64) *clientLimiter {
	return &clientLimiter{rate: rate, burst: burst, buckets: map[string]*bucket{}}
}

// allow takes a token from client's bucket at now, reporting whether
// there was one.
func (l *clientLimiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.buckets[client]
	if !ok {
		if len(l.buckets) >= maxLimitedClients {
			for k, old := range l.buckets {
				if l.refill(old, now) >= l.burst {
					delete(l.buckets, k)
				}
			}
			if len(l.buckets) >= maxLimitedClients {
				return false
			}
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[client] = b
	}
	b.tokens, b.at = l.refill(b, now), now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// refill is b's tokens at now.
func (l *clientLimiter) refill(b *bucket, now time.Time) float64 {
	tokens := b.tokens
	if elapsed := now.Sub(b.at).Seconds(); elapsed > 0 {
		tokens += elapsed * l.rate
	}
	return min(tokens, l.burst)
}
