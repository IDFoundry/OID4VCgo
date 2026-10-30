package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// TransactionStore is a verifier.TransactionStore, for
// verifier.NewTransactions. Each transaction is kept as its
// TransactionCodec encodes it — sealed by the codec's Sealer, if it has
// one — beside the columns its lookups and Sweep go by: KeyID,
// ResponseCodeHash, Owner and RetainUntil.
type TransactionStore struct {
	t *table[verifier.Transaction]
}

// Transactions returns d's verifier.TransactionStore, encoding
// transactions with codec. Give codec a Sealer (verifier.AESGCMSealer,
// with a key kept outside the database) wherever the database is
// shared, backed up or readable by more than the Verifier: it seals
// each transaction's response decryption key and the claims the holder
// disclosed. The DB's own Options.Sealer doesn't apply here.
func (d *DB) Transactions(codec verifier.TransactionCodec) *TransactionStore {
	return &TransactionStore{&table[verifier.Transaction]{
		d: d, name: "verifier_transactions", extra: []string{"key_id", "response_code_hash"},
		encode: func(_ string, tx verifier.Transaction) ([]byte, error) { return codec.Marshal(tx) },
		decode: func(id string, data []byte) (verifier.Transaction, error) {
			tx, err := codec.Unmarshal(data)
			if err != nil {
				return tx, fmt.Errorf("%w: %v", ErrRecordFormat, err)
			}
			if tx.ID != id {
				return verifier.Transaction{}, fmt.Errorf("%w: transaction %q is stored as %q", ErrRecordFormat, tx.ID, id)
			}
			return tx, nil
		},
		rowOf: func(tx verifier.Transaction) row {
			return row{owner: tx.Owner, sweepAfter: tx.RetainUntil, extra: []any{tx.KeyID, tx.ResponseCodeHash}}
		},
	}}
}

// txUnknown turns errNoRow into verifier.ErrTransactionUnknown.
func txUnknown(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNoRow):
		return fmt.Errorf("sqlstore: %s transaction: %w", op, verifier.ErrTransactionUnknown)
	}
	return fmt.Errorf("sqlstore: %s transaction: %w", op, err)
}

// Create implements verifier.TransactionStore.
func (s *TransactionStore) Create(ctx context.Context, tx verifier.Transaction) error {
	return txUnknown("create", s.t.insert(ctx, tx.ID, tx))
}

// Get implements verifier.TransactionStore.
func (s *TransactionStore) Get(ctx context.Context, id string) (verifier.Transaction, error) {
	tx, err := s.t.get(ctx, id)
	return tx, txUnknown("get", err)
}

// Update implements verifier.TransactionStore, in one transaction
// holding the transaction's row. fn is called once.
func (s *TransactionStore) Update(ctx context.Context, id string, fn func(*verifier.Transaction) error) error {
	var fnErr error
	err := s.t.update(ctx, id, func(tx *verifier.Transaction) error {
		fnErr = fn(tx)
		return fnErr
	}, func(tx verifier.Transaction) string { return tx.ID })
	if fnErr != nil {
		return fnErr
	}
	return txUnknown("update", err)
}

// IDByKeyID implements verifier.TransactionStore.
func (s *TransactionStore) IDByKeyID(ctx context.Context, kid string) (string, error) {
	return s.idBy(ctx, sqlTransactionByKeyID, kid)
}

// IDByResponseCode implements verifier.TransactionStore.
func (s *TransactionStore) IDByResponseCode(ctx context.Context, codeHash string) (string, error) {
	return s.idBy(ctx, sqlTransactionByResponseCode, codeHash)
}

// The statements idBy finds a transaction's id with.
const (
	sqlTransactionByKeyID        = "SELECT id FROM {verifier_transactions} WHERE key_id = ?"
	sqlTransactionByResponseCode = "SELECT id FROM {verifier_transactions} WHERE response_code_hash = ?"
)

func (s *TransactionStore) idBy(ctx context.Context, statement, value string) (string, error) {
	if value == "" {
		return "", txUnknown("find", errNoRow)
	}
	var id string
	err := s.t.d.db.QueryRowContext(ctx, s.t.d.q(statement), value).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		err = errNoRow
	}
	return id, txUnknown("find", err)
}

// Capabilities implements verifier.StoreAssurance: Durable, and
// AtomicUpdate across every process sharing the database.
func (s *TransactionStore) Capabilities() verifier.StoreCapabilities {
	return verifier.StoreCapabilities{Durable: true, AtomicUpdate: true}
}
