package issuerapp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"slices"
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
// A passport the holder chose to keep for refresh is kept instead, for
// keepFor after its first credential is issued, so the wallet's refresh
// token can fetch fresh copies (OID4VCI 1.0 §13.5); its credentials are
// issued again on each request. The refresh token, issued before that
// first credential and lasting keepFor too, expires before the passport
// does. Forgetting it, or the wallet revoking the grant, drops it at
// once.
//
// A transaction is redeemed once: the first approval with the right
// confirmation code claims it, after which no other authorization can
// reach it, and that authorization's (DPoP-bound) access token can
// fetch each offered credential once.
type transactions struct {
	mu       sync.Mutex
	now      func() time.Time
	lifetime time.Duration
	keepFor  time.Duration
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
	keep      bool            // kept for refresh: re-issued until expiresAt
	kept      bool            // keep, and expiresAt is now the keepFor deadline
	uploaded  time.Time
	issued    int // credentials issued
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
	errNotOffered          = errors.New("issuerapp: this credential wasn't offered for this passport")
)

// keepMargin is how much longer than keepFor a kept passport outlasts
// its first credential: past the refresh token, issued before it.
const keepMargin = time.Minute

func newTransactions(now func() time.Time, lifetime, keepFor time.Duration, max int) *transactions {
	return &transactions{now: now, lifetime: lifetime, keepFor: keepFor, max: max, items: make(map[string]*transaction)}
}

// put stores e, redeemable once for each of configIDs — or, with keep,
// re-issuable for refresh — under a fresh ID with a fresh confirmation
// code, and returns both, or errTooManyTransactions when max unexpired
// passports are already held.
func (t *transactions) put(e passport.Evidence, configIDs []string, review, keep bool) (id, code string, err error) {
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
	t.prune()
	if len(t.items) >= t.max {
		return "", "", errTooManyTransactions
	}
	now := t.now()
	t.items[id] = &transaction{
		evidence: e, code: code, expiresAt: now.Add(t.lifetime), pending: pending, review: review, keep: keep, uploaded: now,
	}
	return id, code, nil
}

// prune drops every expired transaction. Called with t.mu held.
func (t *transactions) prune() {
	now := t.now()
	for k, v := range t.items {
		if !now.Before(v.expiresAt) {
			delete(t.items, k)
		}
	}
}

// lookup returns the unexpired transaction under id, dropping it if it
// has expired. Called with t.mu held.
func (t *transactions) lookup(id string) (*transaction, bool) {
	v, ok := t.items[id]
	if !ok {
		return nil, false
	}
	if !t.now().Before(v.expiresAt) {
		delete(t.items, id)
		return nil, false
	}
	return v, true
}

// keeps reports whether the unexpired transaction under id is kept for
// refresh.
func (t *transactions) keeps(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.lookup(id)
	return ok && v.keep
}

// dontKeep stops keeping the transaction under id for refresh, for an
// authorization that asked for no refresh token: its credentials are
// then issued once, as without keep.
func (t *transactions) dontKeep(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if v, ok := t.lookup(id); ok && !v.kept {
		v.keep = false
	}
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
// no other request can issue it again — unless it's kept for refresh,
// whose keepFor deadline the first credential starts. Call release if
// issuing then fails, or done if it succeeds.
func (t *transactions) reserve(id, configID string) (passport.Evidence, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.lookup(id)
	if !ok || !v.claimed {
		return passport.Evidence{}, false, errNoTransaction
	}
	pending, offered := v.pending[configID]
	switch {
	case !offered:
		return passport.Evidence{}, false, errNotOffered
	case !pending && !v.keep:
		return passport.Evidence{}, false, errAlreadyIssued
	}
	v.pending[configID] = false
	if v.keep && !v.kept {
		v.kept, v.expiresAt = true, t.now().Add(t.keepFor+keepMargin)
	}
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

// done records a credential issued, and drops the transaction — and its
// passport data — once every offered credential has been, unless it's
// kept for refresh.
func (t *transactions) done(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.items[id]
	if !ok {
		return
	}
	if v.issued++; v.keep {
		return
	}
	for _, pending := range v.pending {
		if pending {
			return
		}
	}
	delete(t.items, id)
}

// forget drops the transaction under id and its passport data, if it's
// still held. Safe to repeat.
func (t *transactions) forget(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.items, id)
}

// keptTransaction is one passport kept for refresh, as the kept page
// lists it: no passport data, only when it was uploaded, until when it's
// kept, and how many credentials it has issued.
type keptTransaction struct {
	id       string
	ref      string
	uploaded time.Time
	until    time.Time
	issued   int
}

// keptRef is the reference the kept page names a transaction by: not its
// ID, which is the access token's subject.
func keptRef(id string) string {
	h := sha256.Sum256([]byte("issuerapp kept " + id))
	return base64.RawURLEncoding.EncodeToString(h[:9])
}

// kept lists the passports kept for refresh, oldest first, dropping any
// that have expired.
func (t *transactions) kept() []keptTransaction {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.prune()
	var out []keptTransaction
	for id, v := range t.items {
		if v.kept {
			out = append(out, keptTransaction{id: id, ref: keptRef(id), uploaded: v.uploaded, until: v.expiresAt, issued: v.issued})
		}
	}
	slices.SortFunc(out, func(a, b keptTransaction) int { return a.uploaded.Compare(b.uploaded) })
	return out
}
