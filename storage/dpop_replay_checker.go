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
	mu   sync.Mutex
	seen map[string]bool
}

// NewDPoPReplayChecker builds an empty DPoPReplayChecker.
func NewDPoPReplayChecker() *DPoPReplayChecker {
	return &DPoPReplayChecker{seen: make(map[string]bool)}
}

// UseOnce implements issuer.DPoPReplayChecker.
func (s *DPoPReplayChecker) UseOnce(_ context.Context, jti string, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.seen[jti] {
		return fmt.Errorf("storage: dpop proof jti %q already used", jti)
	}
	s.seen[jti] = true
	return nil
}
