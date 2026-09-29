package storage

import (
	"context"
	"fmt"
	"sync"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// VerifierTransactionStore is an in-memory verifier.TransactionStore:
// one lock serializes every Update, which is what makes a transaction
// complete — and a response_code redeem — at most once. Like everything
// in this package it's for development and testing only; it doesn't
// implement verifier.StoreAssurance, so verifier.NewTransactions refuses
// it under verifier.AssuranceProduction. Transactions are kept until
// the process exits.
type VerifierTransactionStore struct {
	mu     sync.Mutex
	byID   map[string]verifier.Transaction
	byKey  map[string]string
	byCode map[string]string
}

// NewVerifierTransactionStore returns an empty VerifierTransactionStore.
func NewVerifierTransactionStore() *VerifierTransactionStore {
	return &VerifierTransactionStore{
		byID: map[string]verifier.Transaction{}, byKey: map[string]string{}, byCode: map[string]string{},
	}
}

// Create implements verifier.TransactionStore.
func (s *VerifierTransactionStore) Create(_ context.Context, tx verifier.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tx.ID == "" {
		return fmt.Errorf("storage: transaction ID is required")
	}
	if _, used := s.byID[tx.ID]; used {
		return fmt.Errorf("storage: transaction ID is already in use")
	}
	if _, used := s.byKey[tx.KeyID]; used && tx.KeyID != "" {
		return fmt.Errorf("storage: transaction key ID is already in use")
	}
	s.save(tx)
	return nil
}

// Get implements verifier.TransactionStore.
func (s *VerifierTransactionStore) Get(_ context.Context, id string) (verifier.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.byID[id]
	if !ok {
		return verifier.Transaction{}, verifier.ErrTransactionUnknown
	}
	return tx, nil
}

// Update implements verifier.TransactionStore.
func (s *VerifierTransactionStore) Update(_ context.Context, id string, fn func(*verifier.Transaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.byID[id]
	if !ok {
		return verifier.ErrTransactionUnknown
	}
	previousCode := tx.ResponseCodeHash
	if err := fn(&tx); err != nil {
		return err
	}
	tx.ID = id
	if previousCode != "" && previousCode != tx.ResponseCodeHash {
		delete(s.byCode, previousCode)
	}
	s.save(tx)
	return nil
}

// IDByKeyID implements verifier.TransactionStore.
func (s *VerifierTransactionStore) IDByKeyID(_ context.Context, kid string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byKey[kid]
	if !ok || kid == "" {
		return "", verifier.ErrTransactionUnknown
	}
	return id, nil
}

// IDByResponseCode implements verifier.TransactionStore.
func (s *VerifierTransactionStore) IDByResponseCode(_ context.Context, codeHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byCode[codeHash]
	if !ok || codeHash == "" {
		return "", verifier.ErrTransactionUnknown
	}
	return id, nil
}

// save stores tx and its indexes. Called with s.mu held.
func (s *VerifierTransactionStore) save(tx verifier.Transaction) {
	s.byID[tx.ID] = tx
	if tx.KeyID != "" {
		s.byKey[tx.KeyID] = tx.ID
	}
	if tx.ResponseCodeHash != "" {
		s.byCode[tx.ResponseCodeHash] = tx.ID
	}
}
