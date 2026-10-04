package storage

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// DPoPReplayChecker is an in-memory issuer.DPoPReplayChecker: it
// remembers every "jti" UseOnce has ever seen and rejects a repeat,
// per RFC 9449 §11.1's own "MUST reject any DPoP proof in which the
// jti has been seen before". expiresAt is accepted only to satisfy
// the interface — this store never evicts an entry, so a jti is
// rejected as reused indefinitely, past its own DPoP proof's validity
// window. See the package doc comment for why that's development/
// testing only.
type DPoPReplayChecker struct {
	mu    sync.Mutex
	seen  map[string]time.Time // until when each jti is remembered
	prune pruner
}

// NewDPoPReplayChecker builds an empty DPoPReplayChecker.
func NewDPoPReplayChecker() *DPoPReplayChecker {
	return &DPoPReplayChecker{seen: make(map[string]time.Time)}
}

// UseOnce implements issuer.DPoPReplayChecker.
func (s *DPoPReplayChecker) UseOnce(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, seen := s.seen[jti]; seen {
		return fmt.Errorf("storage: dpop proof jti %q already used", jti)
	}
	// A proof past expiresAt is refused for its age, so its jti needn't
	// be remembered beyond it.
	if now, ok := s.prune.due(len(s.seen)); ok {
		pruneMap(s.seen, now, func(until time.Time) time.Time { return until })
		s.prune.pruned(len(s.seen))
	}
	s.seen[jti] = expiresAt
	return nil
}
