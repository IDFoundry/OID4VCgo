package storage

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// PreAuthorizedCodeStore is an in-memory issuer.PreAuthorizedCodeStore.
// See the package doc comment for why this is development/testing
// only.
type PreAuthorizedCodeStore struct {
	mu       sync.Mutex
	issued   map[string]issuer.PreAuthorizedCodeRecord
	attempts map[string]int
}

// NewPreAuthorizedCodeStore builds an empty PreAuthorizedCodeStore.
func NewPreAuthorizedCodeStore() *PreAuthorizedCodeStore {
	return &PreAuthorizedCodeStore{
		issued:   make(map[string]issuer.PreAuthorizedCodeRecord),
		attempts: make(map[string]int),
	}
}

// Issue implements issuer.PreAuthorizedCodeStore.
func (s *PreAuthorizedCodeStore) Issue(_ context.Context, code string, record issuer.PreAuthorizedCodeRecord) error {
	record.Scopes = cloneStrings(record.Scopes)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.issued[code] = record
	return nil
}

// Consume implements issuer.PreAuthorizedCodeStore. A record is only
// deleted once it's actually being handed back as a successful
// redemption — a TxCode mismatch returns issuer.ErrWrongTxCode and
// leaves the entry in place, so a mistyped PIN can be retried instead
// of permanently destroying the code (see the interface's own doc
// comment for why that distinction matters), but does increment this
// code's own attempts counter, returned as wrongAttempts — the whole
// mutex-held critical section makes this atomic with the check itself,
// so concurrent wrong guesses against the same code each observe a
// distinct, correctly-incrementing count. A record with no TxCode
// requirement is always consumed on a successful lookup, the same
// unconditional-delete-on-success shape NonceStore.Consume already
// establishes.
func (s *PreAuthorizedCodeStore) Consume(_ context.Context, code, wantTxCode string) (issuer.PreAuthorizedCodeRecord, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[code]
	if !ok {
		return issuer.PreAuthorizedCodeRecord{}, 0, fmt.Errorf("storage: unknown or already-consumed pre-authorized_code")
	}
	if record.TxCode != "" && subtle.ConstantTimeCompare([]byte(wantTxCode), []byte(record.TxCode)) != 1 {
		s.attempts[code]++
		return issuer.PreAuthorizedCodeRecord{}, s.attempts[code], issuer.ErrWrongTxCode
	}
	delete(s.issued, code)
	delete(s.attempts, code)
	record.Scopes = cloneStrings(record.Scopes)
	return record, 0, nil
}

// Invalidate implements issuer.PreAuthorizedCodeStore.
func (s *PreAuthorizedCodeStore) Invalidate(_ context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.issued, code)
	delete(s.attempts, code)
	return nil
}
