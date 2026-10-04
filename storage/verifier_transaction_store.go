package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// VerifierTransactionStore is an in-memory verifier.TransactionStore:
// one lock serializes every Update, which is what makes a transaction
// complete — and a response_code redeem — at most once. Like everything
// in this package it's for development and testing only; it doesn't
// implement verifier.StoreAssurance, so verifier.NewTransactions refuses
// it under verifier.AssuranceProduction. Transactions are kept until
// the process exits. Every slice in a Transaction's Query and its
// BrowserBindingHash are copied in and out; its ResponseDecryptionKey
// and Result are shared, as values nothing modifies once set.
type VerifierTransactionStore struct {
	mu     sync.Mutex
	byID   map[string]verifier.Transaction
	byKey  map[string]string
	byCode map[string]string
	prune  pruner
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
	if now, ok := s.prune.due(len(s.byID)); ok {
		s.dropExpired(now)
		s.prune.pruned(len(s.byID))
	}
	s.save(cloneTransaction(tx))
	return nil
}

// dropExpired forgets transactions that expired more than expiryGrace
// before now, with their indexes.
func (s *VerifierTransactionStore) dropExpired(now time.Time) {
	pruneMap(s.byID, now, func(tx verifier.Transaction) time.Time {
		if tx.ExpiresAt.IsZero() {
			return time.Time{}
		}
		return tx.ExpiresAt.Add(expiryGrace)
	})
	for _, index := range []map[string]string{s.byKey, s.byCode} {
		for k, id := range index {
			if _, ok := s.byID[id]; !ok {
				delete(index, k)
			}
		}
	}
}

// Get implements verifier.TransactionStore.
func (s *VerifierTransactionStore) Get(_ context.Context, id string) (verifier.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, ok := s.byID[id]
	if !ok {
		return verifier.Transaction{}, verifier.ErrTransactionUnknown
	}
	return cloneTransaction(tx), nil
}

// Update implements verifier.TransactionStore.
func (s *VerifierTransactionStore) Update(_ context.Context, id string, fn func(*verifier.Transaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.byID[id]
	if !ok {
		return verifier.ErrTransactionUnknown
	}
	tx := cloneTransaction(stored)
	previousCode := tx.ResponseCodeHash
	if err := fn(&tx); err != nil {
		return err
	}
	tx.ID = id
	if previousCode != "" && previousCode != tx.ResponseCodeHash {
		delete(s.byCode, previousCode)
	}
	s.save(cloneTransaction(tx))
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

// cloneTransaction returns a copy of tx that shares no slice with it —
// see cloneStrings' own doc comment.
func cloneTransaction(tx verifier.Transaction) verifier.Transaction {
	tx.Query = cloneQuery(tx.Query)
	if tx.BrowserBindingHash != nil {
		tx.BrowserBindingHash = append([]byte(nil), tx.BrowserBindingHash...)
	}
	return tx
}

// cloneQuery returns a deep copy of q.
func cloneQuery(q dcql.Query) dcql.Query {
	if q.Credentials != nil {
		credentials := make([]dcql.CredentialQuery, len(q.Credentials))
		for i, c := range q.Credentials {
			credentials[i] = cloneCredentialQuery(c)
		}
		q.Credentials = credentials
	}
	if q.CredentialSets != nil {
		sets := make([]dcql.CredentialSetQuery, len(q.CredentialSets))
		for i, set := range q.CredentialSets {
			set.Options = cloneStringSets(set.Options)
			set.Required = cloneBool(set.Required)
			sets[i] = set
		}
		q.CredentialSets = sets
	}
	return q
}

func cloneCredentialQuery(c dcql.CredentialQuery) dcql.CredentialQuery {
	if c.Meta != nil {
		c.Meta = append(json.RawMessage(nil), c.Meta...)
	}
	if c.TrustedAuthorities != nil {
		authorities := make([]dcql.TrustedAuthoritiesQuery, len(c.TrustedAuthorities))
		for i, a := range c.TrustedAuthorities {
			a.Values = cloneStrings(a.Values)
			authorities[i] = a
		}
		c.TrustedAuthorities = authorities
	}
	c.RequireCryptographicHolderBinding = cloneBool(c.RequireCryptographicHolderBinding)
	if c.Claims != nil {
		claims := make([]dcql.ClaimsQuery, len(c.Claims))
		for i, claim := range c.Claims {
			if claim.Path != nil {
				claim.Path = append(dcql.Path(nil), claim.Path...)
			}
			if claim.Values != nil {
				// Each value is a JSON scalar (string, number or bool), so
				// copying the slice copies the values.
				claim.Values = append([]any(nil), claim.Values...)
			}
			claims[i] = claim
		}
		c.Claims = claims
	}
	c.ClaimSets = cloneStringSets(c.ClaimSets)
	return c
}

func cloneStringSets(sets [][]string) [][]string {
	if sets == nil {
		return nil
	}
	out := make([][]string, len(sets))
	for i, set := range sets {
		out[i] = cloneStrings(set)
	}
	return out
}

func cloneBool(b *bool) *bool {
	if b == nil {
		return nil
	}
	v := *b
	return &v
}
