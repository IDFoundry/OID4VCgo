package issuerapp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// transactions holds verified passports awaiting issuance, keyed by an
// unguessable ID that doubles as the Credential Offer's issuer_state
// and the access token's subject. Entries live in memory only and
// expire after the configured lifetime — the raw passport data is
// never persisted.
type transactions struct {
	mu       sync.Mutex
	now      func() time.Time
	lifetime time.Duration
	items    map[string]transaction
}

type transaction struct {
	evidence  passport.Evidence
	expiresAt time.Time
}

func newTransactions(now func() time.Time, lifetime time.Duration) *transactions {
	return &transactions{now: now, lifetime: lifetime, items: make(map[string]transaction)}
}

// put stores e under a fresh ID and returns it.
func (t *transactions) put(e passport.Evidence) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("issuerapp: transaction id: %w", err)
	}
	id := base64.RawURLEncoding.EncodeToString(b[:])

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, v := range t.items {
		if !now.Before(v.expiresAt) {
			delete(t.items, k)
		}
	}
	t.items[id] = transaction{evidence: e, expiresAt: now.Add(t.lifetime)}
	return id, nil
}

// get returns the Evidence stored under id, if it exists and hasn't
// expired. Entries aren't consumed on read: one passport may be issued
// in both formats, and in batches, until it expires.
func (t *transactions) get(id string) (passport.Evidence, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.items[id]
	if !ok || !t.now().Before(v.expiresAt) {
		return passport.Evidence{}, false
	}
	return v.evidence, true
}

// ttlMap is a small thread-safe map with per-entry expiry and
// single-use reads, for the short-lived links the authorization flow
// needs (request_uri → transaction, interaction handle → approval).
type ttlMap[V any] struct {
	mu    sync.Mutex
	now   func() time.Time
	items map[string]ttlEntry[V]
}

type ttlEntry[V any] struct {
	value     V
	expiresAt time.Time
}

func newTTLMap[V any](now func() time.Time) *ttlMap[V] {
	return &ttlMap[V]{now: now, items: make(map[string]ttlEntry[V])}
}

func (m *ttlMap[V]) put(key string, value V, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	for k, v := range m.items {
		if !now.Before(v.expiresAt) {
			delete(m.items, k)
		}
	}
	m.items[key] = ttlEntry[V]{value: value, expiresAt: now.Add(ttl)}
}

// take returns and removes the value under key, if it hasn't expired.
func (m *ttlMap[V]) take(key string) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.items[key]
	delete(m.items, key)
	if !ok || !m.now().Before(v.expiresAt) {
		var zero V
		return zero, false
	}
	return v.value, true
}
