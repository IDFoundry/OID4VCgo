package storage

import "time"

// minPruneAt is how many entries a store holds before it first looks
// for expired ones.
const minPruneAt = 1024

// expiryGrace is how long past its expiry a verifier transaction is
// kept, for a late poll to find it expired rather than unknown.
const expiryGrace = 10 * time.Minute

// pruner decides when a store drops expired entries: whenever it has
// grown to twice what was left after the last time, so the cost stays
// constant per write. Expired entries are what an unauthenticated
// caller — a /nonce request, a DPoP proof, a verifier page — adds and
// never redeems; without pruning they'd stay for the life of the
// process.
type pruner struct {
	at  int
	now func() time.Time
}

// due reports whether a store holding n entries should prune now, and
// the time to prune against.
func (p *pruner) due(n int) (time.Time, bool) {
	if n < max(p.at, minPruneAt) {
		return time.Time{}, false
	}
	if p.now == nil {
		return time.Now(), true
	}
	return p.now(), true
}

// pruned records that n entries were left.
func (p *pruner) pruned(n int) { p.at = 2 * n }

// pruneMap deletes m's entries that expired, by expiresAt, before now.
func pruneMap[K comparable, V any](m map[K]V, now time.Time, expiresAt func(V) time.Time) {
	for k, v := range m {
		if e := expiresAt(v); !e.IsZero() && now.After(e) {
			delete(m, k)
		}
	}
}
