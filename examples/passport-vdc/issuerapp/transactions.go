package issuerapp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

// transactions holds verified passports awaiting issuance, keyed by an
// unguessable ID that doubles as the Credential Offer's issuer_state
// and the access token's subject. Entries live in memory only — the raw
// passport data is never persisted — and are dropped when every offered
// credential has been issued, when they expire, or after too many wrong
// confirmation codes.
//
// A transaction is redeemed once: the first approval with the right
// confirmation code claims it, after which no other authorization can
// reach it, and that authorization's (DPoP-bound) access token can
// fetch each offered credential once.
type transactions struct {
	mu       sync.Mutex
	now      func() time.Time
	lifetime time.Duration
	max      int
	items    map[string]*transaction
}

type transaction struct {
	evidence  passport.Evidence
	code      string
	expiresAt time.Time
	claimed   bool
	failures  int
	pending   map[string]bool // offered configuration ID → not yet issued
	review    bool            // defer issuance until an operator decides
}

// maxCodeFailures is how many wrong confirmation codes void a
// transaction — a million codes, a handful of guesses.
const maxCodeFailures = 5

var (
	// errTooManyTransactions is returned by put when max passports are
	// already held.
	errTooManyTransactions = errors.New("issuerapp: too many passports awaiting issuance")
	errNoTransaction       = errors.New("issuerapp: the passport transaction is unknown or has expired")
	errAlreadyRedeemed     = errors.New("issuerapp: this credential offer has already been redeemed")
	errWrongCode           = errors.New("issuerapp: the confirmation code is wrong")
	errTooManyWrongCodes   = errors.New("issuerapp: too many wrong confirmation codes — the offer is void; upload the passport again")
	errAlreadyIssued       = errors.New("issuerapp: this credential has already been issued for this passport")
)

func newTransactions(now func() time.Time, lifetime time.Duration, max int) *transactions {
	return &transactions{now: now, lifetime: lifetime, max: max, items: make(map[string]*transaction)}
}

// put stores e, redeemable once for each of configIDs, under a fresh ID
// with a fresh confirmation code, and returns both — or
// errTooManyTransactions when max unexpired passports are already held.
func (t *transactions) put(e passport.Evidence, configIDs []string, review bool) (id, code string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("issuerapp: transaction id: %w", err)
	}
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", "", fmt.Errorf("issuerapp: confirmation code: %w", err)
	}
	id, code = base64.RawURLEncoding.EncodeToString(b[:]), fmt.Sprintf("%06d", n.Int64())
	pending := make(map[string]bool, len(configIDs))
	for _, c := range configIDs {
		pending[c] = true
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for k, v := range t.items {
		if !now.Before(v.expiresAt) {
			delete(t.items, k)
		}
	}
	if len(t.items) >= t.max {
		return "", "", errTooManyTransactions
	}
	t.items[id] = &transaction{evidence: e, code: code, expiresAt: now.Add(t.lifetime), pending: pending, review: review}
	return id, code, nil
}

// lookup returns the unexpired transaction under id. Called with t.mu
// held.
func (t *transactions) lookup(id string) (*transaction, bool) {
	v, ok := t.items[id]
	if !ok || !t.now().Before(v.expiresAt) {
		return nil, false
	}
	return v, true
}

// unclaimed returns the Evidence of an unexpired transaction no approval
// has claimed yet — what may still start an authorization.
func (t *transactions) unclaimed(id string) (passport.Evidence, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.lookup(id)
	switch {
	case !ok:
		return passport.Evidence{}, errNoTransaction
	case v.claimed:
		return passport.Evidence{}, errAlreadyRedeemed
	}
	return v.evidence, nil
}

// claim redeems the transaction for one authorization, if code is its
// confirmation code. A wrong code counts against it; maxCodeFailures of
// them void it.
func (t *transactions) claim(id, code string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.lookup(id)
	switch {
	case !ok:
		return errNoTransaction
	case v.claimed:
		return errAlreadyRedeemed
	case subtle.ConstantTimeCompare([]byte(code), []byte(v.code)) != 1:
		if v.failures++; v.failures >= maxCodeFailures {
			delete(t.items, id)
			return errTooManyWrongCodes
		}
		return errWrongCode
	}
	v.claimed = true
	return nil
}

// reserve returns the Evidence of a claimed transaction for issuing
// configID, and whether it was uploaded for review, marking it issued so
// no other request can issue it again. Call release if issuing then
// fails, or done if it succeeds.
func (t *transactions) reserve(id, configID string) (passport.Evidence, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.lookup(id)
	switch {
	case !ok || !v.claimed:
		return passport.Evidence{}, false, errNoTransaction
	case !v.pending[configID]:
		return passport.Evidence{}, false, errAlreadyIssued
	}
	v.pending[configID] = false
	return v.evidence, v.review, nil
}

// release undoes reserve after issuing configID failed.
func (t *transactions) release(id, configID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.items[id]; ok {
		v.pending[configID] = true
	}
}

// done drops the transaction — and its passport data — once every
// offered credential has been issued.
func (t *transactions) done(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.items[id]
	if !ok {
		return
	}
	for _, pending := range v.pending {
		if pending {
			return
		}
	}
	delete(t.items, id)
}

// ttlMap is a small thread-safe map with per-entry expiry and
// single-use reads, for the short-lived links the authorization flow
// needs (interaction handle → approval).
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
