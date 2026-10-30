package sqlstore

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"

	"github.com/idfoundry/oid4vcgo/issuer"
)

// ErrNotFound is what CredentialOfferStore.Get returns, wrapped, for a
// reference it holds no offer for: issuer.CredentialOfferStore defines
// no error of its own for that.
var ErrNotFound = errors.New("sqlstore: not found")

// issuerCapabilities is what every issuer store declares: its records
// survive a restart, and each consume-once operation is one
// transaction, atomic across every process sharing the database.
var issuerCapabilities = issuer.StoreCapabilities{Durable: true, AtomicConsume: true}

// NonceStore is an issuer.NonceStore: Dependencies.Nonces.
type NonceStore struct{ t *table[issuer.NonceIssuance] }

// Nonces returns d's issuer.NonceStore.
func (d *DB) Nonces() *NonceStore {
	return &NonceStore{&table[issuer.NonceIssuance]{d: d, name: "issuer_nonces", sql: tableSQL{insert: d.sql.nonceInsert, consume: d.sql.nonceConsumeOwned}, rowOf: func(n issuer.NonceIssuance) row {
		return row{owner: n.Owner, sweepAfter: n.ExpiresAt}
	}}}
}

// Issue implements issuer.NonceStore.
func (s *NonceStore) Issue(ctx context.Context, issuance issuer.NonceIssuance) error {
	if err := s.t.insert(ctx, issuance.Nonce, issuance); err != nil {
		return fmt.Errorf("sqlstore: issue c_nonce: %w", err)
	}
	return nil
}

// Consume implements issuer.NonceStore: one DELETE … RETURNING, of the
// nonce issued with consumption.Owner only.
func (s *NonceStore) Consume(ctx context.Context, consumption issuer.NonceConsumption) (issuer.NonceRecord, error) {
	n, err := s.t.consume(ctx, consumption.Nonce, consumption.Owner)
	switch {
	case errors.Is(err, errNoRow):
		return issuer.NonceRecord{}, fmt.Errorf("sqlstore: %w", issuer.ErrNonceUnknown)
	case err != nil:
		return issuer.NonceRecord{}, fmt.Errorf("sqlstore: consume c_nonce: %w", err)
	}
	return issuer.NonceRecord{Owner: n.Owner, ExpiresAt: n.ExpiresAt}, nil
}

// Capabilities implements issuer.StoreAssurance: Durable and
// AtomicConsume.
func (s *NonceStore) Capabilities() issuer.StoreCapabilities { return issuerCapabilities }

// PreAuthorizedCodeStore is an issuer.PreAuthorizedCodeStore:
// Dependencies.PreAuthorizedCodes. It keeps what the issuer gives it:
// the hash of each code as its key, and the keyed hash of its
// Transaction Code, never the code or Transaction Code themselves.
type PreAuthorizedCodeStore struct {
	t *table[issuer.PreAuthorizedCodeRecord]
}

// PreAuthorizedCodes returns d's issuer.PreAuthorizedCodeStore.
func (d *DB) PreAuthorizedCodes() *PreAuthorizedCodeStore {
	return &PreAuthorizedCodeStore{&table[issuer.PreAuthorizedCodeRecord]{
		d: d, name: "issuer_pre_authorized_codes", sql: tableSQL{insert: d.sql.pacInsert, delete: d.sql.pacDelete},
		rowOf: func(r issuer.PreAuthorizedCodeRecord) row {
			return row{owner: r.Owner, sweepAfter: r.ExpiresAt, extra: []any{r.TxCodeHash}}
		},
	}}
}

// Issue implements issuer.PreAuthorizedCodeStore.
func (s *PreAuthorizedCodeStore) Issue(ctx context.Context, codeHash string, record issuer.PreAuthorizedCodeRecord) error {
	if err := s.t.insert(ctx, codeHash, record); err != nil {
		return fmt.Errorf("sqlstore: issue pre-authorized code: %w", err)
	}
	return nil
}

// Consume implements issuer.PreAuthorizedCodeStore, in one transaction
// holding the code's row: the tx_code check, the wrong-attempt count,
// accept and the consumption happen together, so concurrent requests
// for one code each see the one before. accept is called once.
func (s *PreAuthorizedCodeStore) Consume(ctx context.Context, codeHash, wantTxCodeHash string, maxAttempts int, accept func(issuer.PreAuthorizedCodeRecord) error) (issuer.PreAuthorizedCodeRecord, int, error) {
	var record issuer.PreAuthorizedCodeRecord
	var wrongAttempts int
	// outcome is a refusal the transaction commits (a counted wrong
	// guess, or the code invalidated) rather than rolls back.
	var outcome error
	err := s.t.d.write(ctx, func(q querier) error {
		var err error
		record, wrongAttempts, outcome, err = s.consumeOn(ctx, q, codeHash, wantTxCodeHash, maxAttempts, accept)
		return err
	})
	switch {
	case errors.Is(err, errNoRow):
		return issuer.PreAuthorizedCodeRecord{}, 0, fmt.Errorf("sqlstore: %w", issuer.ErrPreAuthorizedCodeUnknown)
	case err != nil:
		return issuer.PreAuthorizedCodeRecord{}, 0, err
	case outcome != nil:
		return issuer.PreAuthorizedCodeRecord{}, wrongAttempts, outcome
	}
	return record, 0, nil
}

// consumeOn is Consume's transaction, on q. err rolls it back; outcome,
// with a nil err, is a refusal whose changes commit.
func (s *PreAuthorizedCodeStore) consumeOn(ctx context.Context, q querier, codeHash, wantTxCodeHash string, maxAttempts int, accept func(issuer.PreAuthorizedCodeRecord) error) (record issuer.PreAuthorizedCodeRecord, wrongAttempts int, outcome, err error) {
	d := s.t.d
	var txCodeHash string
	var attempts int
	var data []byte
	err = q.QueryRowContext(ctx, d.sql.pacSelectForConsume, codeHash).
		Scan(&txCodeHash, &attempts, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return record, 0, nil, errNoRow
	}
	if err != nil {
		return record, 0, nil, fmt.Errorf("sqlstore: consume pre-authorized code: %w", err)
	}
	invalidate := func() error {
		_, err := q.ExecContext(ctx, d.sql.pacDelete, codeHash)
		return err
	}
	tooMany := maxAttempts > 0 && attempts >= maxAttempts
	switch {
	case txCodeHash == "" && wantTxCodeHash != "":
		return record, 0, nil, issuer.ErrTxCodeUnexpected
	case txCodeHash != "" && wantTxCodeHash == "" && !tooMany:
		return record, 0, nil, issuer.ErrTxCodeRequired
	case txCodeHash != "" && tooMany:
		if err := invalidate(); err != nil {
			return record, 0, nil, err
		}
		return record, 0, issuer.ErrTooManyTxCodeAttempts, nil
	case txCodeHash != "" && subtle.ConstantTimeCompare([]byte(wantTxCodeHash), []byte(txCodeHash)) != 1:
		attempts++
		if maxAttempts > 0 && attempts >= maxAttempts {
			err = invalidate()
		} else {
			_, err = q.ExecContext(ctx, d.sql.pacSetAttempts, attempts, codeHash)
		}
		if err != nil {
			return record, 0, nil, err
		}
		return record, attempts, issuer.ErrWrongTxCode, nil
	}
	if record, err = s.t.decodeOf(codeHash, data); err != nil {
		return record, 0, nil, err
	}
	if accept != nil {
		if err := accept(record); err != nil {
			return issuer.PreAuthorizedCodeRecord{}, 0, nil, err
		}
	}
	return record, 0, nil, invalidate()
}

// Invalidate implements issuer.PreAuthorizedCodeStore.
func (s *PreAuthorizedCodeStore) Invalidate(ctx context.Context, codeHash string) error {
	if _, err := s.t.remove(ctx, codeHash); err != nil {
		return fmt.Errorf("sqlstore: invalidate pre-authorized code: %w", err)
	}
	return nil
}

// Capabilities implements issuer.StoreAssurance: Durable and
// AtomicConsume.
func (s *PreAuthorizedCodeStore) Capabilities() issuer.StoreCapabilities { return issuerCapabilities }

// DeferredTransactionStore is an issuer.DeferredTransactionStore:
// Dependencies.DeferredTransactions. Invalidate deletes the
// transaction, its Credentials with it.
type DeferredTransactionStore struct {
	t *table[issuer.DeferredTransactionRecord]
}

// DeferredTransactions returns d's issuer.DeferredTransactionStore.
func (d *DB) DeferredTransactions() *DeferredTransactionStore {
	return &DeferredTransactionStore{&table[issuer.DeferredTransactionRecord]{
		d: d, name: "issuer_deferred_transactions", sql: tableSQL{
			insert: d.sql.deferredTxInsert, get: d.sql.deferredTxGet, getForUpdate: d.sql.deferredTxGetForUpdate,
			update: d.sql.deferredTxUpdate, delete: d.sql.deferredTxDelete,
		},
		rowOf: func(r issuer.DeferredTransactionRecord) row { return row{owner: r.Owner, sweepAfter: r.ExpiresAt} },
	}}
}

// deferredUnknown turns errNoRow into issuer.ErrDeferredTransactionUnknown.
func deferredUnknown(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errNoRow):
		return fmt.Errorf("sqlstore: %s deferred transaction: %w", op, issuer.ErrDeferredTransactionUnknown)
	}
	return fmt.Errorf("sqlstore: %s deferred transaction: %w", op, err)
}

// Get implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Get(ctx context.Context, transactionID string) (issuer.DeferredTransactionRecord, error) {
	r, err := s.t.get(ctx, transactionID)
	return r, deferredUnknown("get", err)
}

// Invalidate implements issuer.DeferredTransactionStore: one DELETE, so
// of concurrent calls exactly one succeeds.
func (s *DeferredTransactionStore) Invalidate(ctx context.Context, transactionID string) error {
	found, err := s.t.remove(ctx, transactionID)
	if err == nil && !found {
		err = errNoRow
	}
	return deferredUnknown("invalidate", err)
}

// Create implements issuer.DeferredTransactionStore.
func (s *DeferredTransactionStore) Create(ctx context.Context, transactionID string, record issuer.DeferredTransactionRecord) error {
	return deferredUnknown("create", s.t.insert(ctx, transactionID, record))
}

// Update implements issuer.DeferredTransactionStore, in one transaction
// holding the transaction's row. fn is called once.
func (s *DeferredTransactionStore) Update(ctx context.Context, transactionID string, fn func(*issuer.DeferredTransactionRecord) error) error {
	var fnErr error
	err := s.t.update(ctx, transactionID, func(r *issuer.DeferredTransactionRecord) error {
		fnErr = fn(r)
		return fnErr
	}, nil)
	if fnErr != nil {
		return fnErr
	}
	return deferredUnknown("update", err)
}

// Capabilities implements issuer.StoreAssurance: Durable and
// AtomicConsume.
func (s *DeferredTransactionStore) Capabilities() issuer.StoreCapabilities {
	return issuerCapabilities
}

// NotificationStore is an issuer.NotificationStore:
// Dependencies.Notifications.
type NotificationStore struct {
	t *table[issuer.NotificationRecord]
}

// Notifications returns d's issuer.NotificationStore.
func (d *DB) Notifications() *NotificationStore {
	return &NotificationStore{&table[issuer.NotificationRecord]{
		d: d, name: "issuer_notifications", sql: tableSQL{insert: d.sql.notificationInsert, get: d.sql.notificationGet},
		rowOf: func(r issuer.NotificationRecord) row { return row{owner: r.Owner, sweepAfter: r.ExpiresAt} },
	}}
}

// Issue implements issuer.NotificationStore.
func (s *NotificationStore) Issue(ctx context.Context, notificationID string, record issuer.NotificationRecord) error {
	if err := s.t.insert(ctx, notificationID, record); err != nil {
		return fmt.Errorf("sqlstore: issue notification_id: %w", err)
	}
	return nil
}

// Get implements issuer.NotificationStore.
func (s *NotificationStore) Get(ctx context.Context, notificationID string) (issuer.NotificationRecord, error) {
	r, err := s.t.get(ctx, notificationID)
	switch {
	case errors.Is(err, errNoRow):
		return r, fmt.Errorf("sqlstore: %w", issuer.ErrNotificationIDUnknown)
	case err != nil:
		return r, fmt.Errorf("sqlstore: get notification_id: %w", err)
	}
	return r, nil
}

// Capabilities implements issuer.StoreAssurance: Durable (and
// AtomicConsume, though it has nothing to consume).
func (s *NotificationStore) Capabilities() issuer.StoreCapabilities { return issuerCapabilities }

// CredentialOfferStore is an issuer.CredentialOfferStore:
// Dependencies.CredentialOffers.
type CredentialOfferStore struct {
	t *table[issuer.CredentialOfferRecord]
}

// CredentialOffers returns d's issuer.CredentialOfferStore.
func (d *DB) CredentialOffers() *CredentialOfferStore {
	return &CredentialOfferStore{&table[issuer.CredentialOfferRecord]{
		d: d, name: "issuer_credential_offers", sql: tableSQL{insert: d.sql.offerInsert, get: d.sql.offerGet},
		rowOf: func(r issuer.CredentialOfferRecord) row { return row{sweepAfter: r.ExpiresAt} },
	}}
}

// Store implements issuer.CredentialOfferStore.
func (s *CredentialOfferStore) Store(ctx context.Context, record issuer.CredentialOfferRecord) error {
	if err := s.t.insert(ctx, record.Reference, record); err != nil {
		return fmt.Errorf("sqlstore: store credential offer: %w", err)
	}
	return nil
}

// Get implements issuer.CredentialOfferStore: an unknown reference is an
// error wrapping ErrNotFound.
func (s *CredentialOfferStore) Get(ctx context.Context, reference string) (issuer.CredentialOfferRecord, error) {
	r, err := s.t.get(ctx, reference)
	switch {
	case errors.Is(err, errNoRow):
		return r, fmt.Errorf("sqlstore: credential offer: %w", ErrNotFound)
	case err != nil:
		return r, fmt.Errorf("sqlstore: get credential offer: %w", err)
	}
	return r, nil
}

// Capabilities implements issuer.StoreAssurance: Durable (and
// AtomicConsume, though it has nothing to consume).
func (s *CredentialOfferStore) Capabilities() issuer.StoreCapabilities { return issuerCapabilities }
