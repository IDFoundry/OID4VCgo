package storage

import (
	"context"
	"crypto/subtle"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// PreAuthorizedCodeStore is an in-memory issuer.PreAuthorizedCodeStore.
// See the package doc comment for why this is development/testing
// only. Codes past their ExpiresAt, and their wrong tx_code counts,
// are dropped as the store grows. Like any issuer.PreAuthorizedCodeStore,
// it holds hashes of the codes and Transaction Codes, never the values.
type PreAuthorizedCodeStore struct {
	mu       sync.Mutex
	issued   map[string]issuer.PreAuthorizedCodeRecord
	attempts map[string]int
	prune    pruner
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
	if now, ok := s.prune.due(len(s.issued)); ok {
		pruneMap(s.issued, now, func(r issuer.PreAuthorizedCodeRecord) time.Time { return r.ExpiresAt })
		for c := range s.attempts {
			if _, live := s.issued[c]; !live {
				delete(s.attempts, c)
			}
		}
		s.prune.pruned(len(s.issued))
	}
	s.issued[code] = record
	return nil
}

// Consume implements issuer.PreAuthorizedCodeStore. A record is only
// deleted once it's actually being handed back as a successful
// redemption — a TxCodeHash mismatch returns issuer.ErrWrongTxCode and
// leaves the entry in place, so a mistyped PIN can be retried instead
// of permanently destroying the code (see the interface's own doc
// comment for why that distinction matters), but does increment this
// code's own attempts counter, returned as wrongAttempts — the whole
// mutex-held critical section makes this atomic with the check itself,
// so concurrent wrong guesses against the same code each observe a
// distinct, correctly-incrementing count. A record with no TxCodeHash
// passes the check on a successful lookup. accept runs
// under the same mutex, on a copy of the record, so no concurrent
// Consume can redeem the code between accept's check and the delete.
func (s *PreAuthorizedCodeStore) Consume(_ context.Context, code, wantTxCodeHash string, maxAttempts int, accept func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.issued[code]
	if !ok {
		return issuer.PreAuthorizedCodeRecord{}, 0, fmt.Errorf("storage: %w", issuer.ErrPreAuthorizedCodeUnknown)
	}
	switch {
	case record.TxCodeHash == "" && wantTxCodeHash != "":
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTxCodeUnexpected
	case record.TxCodeHash != "" && wantTxCodeHash == "" && (maxAttempts <= 0 || s.attempts[code] < maxAttempts):
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTxCodeRequired
	}
	if record.TxCodeHash != "" && maxAttempts > 0 && s.attempts[code] >= maxAttempts {
		delete(s.issued, code)
		delete(s.attempts, code)
		return issuer.PreAuthorizedCodeRecord{}, 0, issuer.ErrTooManyTxCodeAttempts
	}
	if record.TxCodeHash != "" && subtle.ConstantTimeCompare([]byte(wantTxCodeHash), []byte(record.TxCodeHash)) != 1 {
		s.attempts[code]++
		attempts := s.attempts[code]
		if maxAttempts > 0 && attempts >= maxAttempts {
			delete(s.issued, code)
			delete(s.attempts, code)
		}
		return issuer.PreAuthorizedCodeRecord{}, attempts, issuer.ErrWrongTxCode
	}
	record.Scopes = cloneStrings(record.Scopes)
	record.CredentialConfigurationIDs = cloneStrings(record.CredentialConfigurationIDs)
	if accept != nil {
		if err := accept(record); err != nil {
			return issuer.PreAuthorizedCodeRecord{}, 0, err
		}
	}
	delete(s.issued, code)
	delete(s.attempts, code)
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
