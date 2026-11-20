package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// sealedTables are the tables whose records a DB seals with its own
// Sealer (encodeRecord), without their oid4vc_ prefix: each keyed by
// its id column, its record in its record column. The verifier's
// transactions, which their TransactionCodec seals, aren't among them.
var sealedTables = []string{
	"issuer_nonces", "issuer_pre_authorized_codes", "issuer_deferred_transactions",
	"issuer_notifications", "issuer_credential_offers",
	"wallet_credentials", "wallet_authorizations", "wallet_grants", "wallet_deferred", "wallet_keys",
	"walletprovider_instances", "walletprovider_instance_keys", "walletprovider_challenges",
}

// bindBatchSize is how many records BindRecords reads, and seals, per
// transaction.
const bindBatchSize = 100

// bindStallLimit is how many passes over a table in a row BindRecords
// lets read records without sealing any before it gives up: a record
// that changes each time it's read would otherwise be read forever.
const bindStallLimit = 3

// BindRecords seals in the DB's SealContext, in place, every record
// sealed without one — before the DB had it — and returns how many it
// sealed. It's the way to move a database to a SealContext:
//
//  1. deploy every process using the database with SealContext set and
//     ReadWithoutSealContext true, so they read the records sealed
//     before and seal each record they write in the SealContext;
//  2. run BindRecords once every process does: a record that a process
//     still without the SealContext writes during a pass can land
//     behind the pass's key-ordered cursor and stay unbound, so if any
//     may have, run it again after;
//  3. deploy again with ReadWithoutSealContext false, so that from
//     then on a record sealed without the SealContext is refused.
//
// It trusts what it finds: a record that a database writer copied in
// from another tenant's tables before it ran, sealed without a
// SealContext under the same key, is bound to this DB's as if it were
// its own, so run it on a database whose contents you trust.
//
// It reads each table in key order, a batch of records per
// transaction, sealing each only if it hasn't changed since it was
// read, so it's safe to run while the stores are in use; a pass that
// finds a record changed before it could seal it is followed by
// another. It stops with an error, wrapping ErrRecordFormat, at a
// record that doesn't open, and when it keeps reading records it can't
// seal. It requires a SealContext.
func (d *DB) BindRecords(ctx context.Context) (int64, error) {
	if d.sealContext == "" {
		return 0, errors.New("sqlstore: bind records: the DB has no SealContext")
	}
	var total int64
	for _, table := range sealedTables {
		n, err := d.bindTable(ctx, table)
		total += n
		if err != nil {
			return total, fmt.Errorf("sqlstore: bind records in %s: %w", table, err)
		}
	}
	return total, nil
}

// bindTable is BindRecords for table: passes over it until one leaves
// no record it read unbound.
func (d *DB) bindTable(ctx context.Context, table string) (int64, error) {
	var total int64
	for stalls := 0; ; {
		bound, missed, err := d.bindPass(ctx, table)
		total += bound
		switch {
		case err != nil:
			return total, err
		case missed == 0:
			return total, nil
		case bound > 0:
			stalls = 0
		default:
			if stalls++; stalls >= bindStallLimit {
				return total, fmt.Errorf("%d records read but none sealed, %d passes in a row: each changed as it was sealed", missed, stalls)
			}
		}
	}
}

// unboundRecord is a record BindRecords is sealing: its key, and the
// record column as read.
type unboundRecord struct {
	id     string
	stored []byte
}

// bindPass reads table once, in key order, sealing in the DB's
// SealContext each record sealed without one, a batch per transaction.
// It returns how many it sealed, and how many it read but didn't seal
// because they changed since.
func (d *DB) bindPass(ctx context.Context, table string) (bound, missed int64, err error) {
	unbound, update := d.bindStatements(table)
	after := ""
	for {
		var recs []unboundRecord
		var n int64
		err := d.write(ctx, func(q querier) error {
			var err error
			if recs, err = unboundRecords(ctx, q, unbound, after); err != nil {
				return err
			}
			n, err = d.sealInContext(ctx, q, table, update, recs)
			return err
		})
		if err != nil {
			return bound, missed, err
		}
		bound += n
		missed += int64(len(recs)) - n
		if len(recs) < bindBatchSize {
			return bound, missed, nil
		}
		after = recs[len(recs)-1].id
	}
}

// bindStatements are BindRecords' statements for table: unbound,
// selecting a batch of its records sealed without a SealContext whose
// keys follow a key, and update, storing a record in place of one
// read. table is one of sealedTables. SQLite keeps a value's own
// storage class in a BLOB column, so a record written as TEXT, by
// hand, is compared as bytes only cast; PostgreSQL's bytea is bytes
// already.
func (d *DB) bindStatements(table string) (unbound, update string) {
	name, batch := "oid4vc_"+table, strconv.Itoa(bindBatchSize)
	if d.dialect == SQLite {
		return "SELECT id, CAST(record AS BLOB) FROM " + name + " WHERE id > ? AND substr(CAST(record AS BLOB), 1, 1) = ? ORDER BY id LIMIT " + batch,
			"UPDATE " + name + " SET record = ? WHERE id = ? AND CAST(record AS BLOB) = ?"
	}
	return "SELECT id, record FROM " + name + " WHERE id > $1 AND substr(record, 1, 1) = $2 ORDER BY id LIMIT " + batch,
		"UPDATE " + name + " SET record = $1 WHERE id = $2 AND record = $3"
}

// unboundRecords runs unbound on q: the records sealed without a
// SealContext whose keys follow after, in key order.
func unboundRecords(ctx context.Context, q querier, unbound, after string) ([]unboundRecord, error) {
	rows, err := q.QueryContext(ctx, unbound, after, []byte{recordSealed})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var recs []unboundRecord
	for rows.Next() {
		var r unboundRecord
		if err := rows.Scan(&r.id, &r.stored); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	return recs, rows.Err()
}

// sealInContext seals each of recs, table's records sealed without a
// SealContext, in the DB's, storing it with update only if it hasn't
// changed since it was read, and returns how many it stored.
func (d *DB) sealInContext(ctx context.Context, q querier, table, update string, recs []unboundRecord) (int64, error) {
	var total int64
	for _, r := range recs {
		plain, err := d.sealer.Open(r.stored[1:], recordAD("", table, r.id))
		if err != nil {
			return 0, fmt.Errorf("%w: open record %q: %v", ErrRecordFormat, r.id, err)
		}
		sealed, err := d.sealer.Seal(plain, recordAD(d.sealContext, table, r.id))
		if err != nil {
			return 0, fmt.Errorf("seal record %q: %w", r.id, err)
		}
		res, err := q.ExecContext(ctx, update, append([]byte{recordSealedInContext}, sealed...), r.id, r.stored)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += n
	}
	return total, nil
}
