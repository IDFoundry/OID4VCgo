package walletprovider

import (
	"container/list"
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	wp "github.com/idfoundry/oid4vcgo/walletprovider"
)

// The challenge endpoint's limit for each client address: a burst of
// challengeBurst, then challengeRate a second. One address can then
// hold at most challengeBurst + challengeRate × ChallengeLifetime (320)
// challenges outstanding, so it takes some 30 addresses, not one, to
// fill maxOutstandingChallenges and lock every Android device out.
const (
	challengeRate  = 1.0
	challengeBurst = 20.0
	// The older protocol's attestation endpoints' limit for each client
	// address, looser than the challenges': each credential a wallet
	// receives takes a Wallet and a Key Attestation, and behind a
	// tunnel every wallet shares one address. It slows a client
	// registering instances; maxDemoInstances bounds them.
	attestationRate  = 2.0
	attestationBurst = 60.0
	// The library protocol's limit for each instance's signed requests
	// (wp.Config.InstanceLimit): a burst of instanceBurst, enough for a
	// wallet receiving or refreshing several credentials at once, a
	// Wallet and a Key Attestation each, then instanceRate a second.
	// Unlike the address limits, it's keyed on the instance the
	// request's signature proved, so wallets sharing a tunnel's address
	// don't share it.
	instanceRate  = 1.0
	instanceBurst = 30.0
	// maxLimitedClients bounds the addresses tracked; past it, the one
	// heard from least recently is forgotten, so a new address is never
	// turned away for want of room.
	maxLimitedClients = 4096
)

// clientAddress is the address a request came from: its connection's
// remote IP, or for IPv6 its /64, which one host commonly has whole. It
// trusts no forwarded-address header, as nothing else in the demo does,
// so behind a tunnel (cloudflared on this machine) every client shares
// the tunnel's address and the limit applies to them all together —
// which still keeps one client from filling the challenge table, but
// lets one slow the others.
func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if addr = addr.Unmap(); addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// clientLimiter is a token bucket for each client address, the most
// recently used first.
type clientLimiter struct {
	rate, burst float64

	mu      sync.Mutex
	buckets map[string]*list.Element // of *bucket
	recent  list.List
}

type bucket struct {
	client string
	tokens float64
	at     time.Time
}

func newClientLimiter(rate, burst float64) *clientLimiter {
	return &clientLimiter{rate: rate, burst: burst, buckets: map[string]*list.Element{}}
}

// allow takes a token from client's bucket at now, reporting whether
// there was one.
func (l *clientLimiter) allow(client string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.buckets[client]
	if ok {
		l.recent.MoveToFront(e)
	} else {
		if len(l.buckets) >= maxLimitedClients {
			oldest := l.recent.Back()
			delete(l.buckets, l.recent.Remove(oldest).(*bucket).client)
		}
		e = l.recent.PushFront(&bucket{client: client, tokens: l.burst, at: now})
		l.buckets[client] = e
	}
	b := e.Value.(*bucket)
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

// instanceLimit is a wp.Config.InstanceLimit taking a token from the
// bucket of the request's instance in l at now(), and refusing the
// request, to retry after one token's time, when there's none.
func instanceLimit(l *clientLimiter, now func() time.Time) func(context.Context, wp.InstanceRequest) error {
	return func(_ context.Context, req wp.InstanceRequest) error {
		if l.allow(req.InstanceID, now()) {
			return nil
		}
		return wp.RateLimited(time.Duration(float64(time.Second) / l.rate))
	}
}
