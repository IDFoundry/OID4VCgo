package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Sweep deletes every issuer, verifier and Wallet Provider record that
// expired before now and returns how many it deleted. The stores never
// delete an expired record themselves — each is answered as unknown,
// or refused, by the issuer, verifier or provider once it has expired
// — so run Sweep periodically (every few minutes, say) to keep the
// tables, and the personal data in them, from growing without bound.
// Run it from every instance: on Postgres, a run that finds another
// sweeping the same schema stops, deleting nothing more, and returns
// what it deleted with no error. On SQLite, whose writes take turns
// anyway, runs at once only delete the same rows.
//
// What "expired" means for each record:
//   - a c_nonce, pre-authorized code or Credential Offer: its ExpiresAt;
//   - a deferred transaction or notification_id: its ExpiresAt, and
//     never when that's zero. To give a Wallet longer to collect a
//     deferred credential after it lapses, pass an earlier now;
//   - a verifier transaction: its RetainUntil, the earliest a store may
//     delete it, and never when that's zero;
//   - a Wallet Provider's challenge: its ExpiresAt;
//   - a Wallet Provider's instance key: its RetainUntil, and never when
//     that's zero, as in a record written before RetainUntil existed
//     until the provider next moves it.
//
// Sweep leaves the wallet's tables alone. An expired authorization in
// progress names the instance and DPoP keys it was started with, which
// walletflow deletes with it when it next lists the authorizations
// (Wallet.KeysInUse, which a wallet should call periodically):
// deleting the authorization here would orphan its keys in the
// KeyStore, which can't list them. A wallet's credentials, refresh
// grants, pending deferred credentials and keys have no expiry here
// either: walletflow deletes them itself. Nor does it touch the Status
// List indices StatusIndices records, which only the lists' issuer
// knows when to delete (walletprovider.Provider.SweepStatusLists does,
// for a Wallet Provider's lists), or a Wallet Provider's registered
// instances, which never expire.
func (d *DB) Sweep(ctx context.Context, now time.Time) (int64, error) {
	// What each table's records say they're good until.
	sweeps := []struct{ table, statement string }{
		{"issuer_nonces", d.sql.nonceSweep},                        // NonceIssuance.ExpiresAt
		{"issuer_pre_authorized_codes", d.sql.pacSweep},            // PreAuthorizedCodeRecord.ExpiresAt
		{"issuer_deferred_transactions", d.sql.deferredTxSweep},    // DeferredTransactionRecord.ExpiresAt; never when zero
		{"issuer_notifications", d.sql.notificationSweep},          // NotificationRecord.ExpiresAt; never when zero
		{"issuer_credential_offers", d.sql.offerSweep},             // CredentialOfferRecord.ExpiresAt
		{"verifier_transactions", d.sql.txSweep},                   // Transaction.RetainUntil; never when zero
		{"walletprovider_challenges", d.sql.wpChallengeSweep},      // ChallengeRecord.ExpiresAt
		{"walletprovider_instance_keys", d.sql.wpInstanceKeySweep}, // InstanceKey.RetainUntil; never when zero
	}
	var total int64
	for _, sw := range sweeps {
		n, err := d.sweepTable(ctx, sw.statement, now)
		total += n
		if errors.Is(err, errSweepLocked) {
			return total, nil
		}
		if err != nil {
			return total, fmt.Errorf("sqlstore: sweep %s: %w", sw.table, err)
		}
	}
	return total, nil
}

// errSweepLocked is sweepTable's answer when another Sweep of the same
// Postgres schema holds the sweep lock.
var errSweepLocked = errors.New("sqlstore: another Sweep is running")

// sweepBatch is about how many rows each of Sweep's writes deletes.
var sweepBatch = 10000

// sweepTable deletes a table's expired rows in batches, each its own
// write, so a sweep after a long pause neither holds one transaction
// open across millions of rows nor, on SQLite, keeps other writers
// waiting for all of it. Each batch deletes the expired rows up to the
// sweep_after of the (sweepBatch+1)th, so sweepBatch+1 of them and any
// expiring in the same second, or every one left when fewer are: a
// batch reads its rows through the sweep_after index, never the ones
// before it already deleted.
//
// On Postgres, each batch first tries for the schema's sweep lock
// (postgresSweepLock), held until it commits, and returns
// errSweepLocked if another Sweep holds it: that one deletes the same
// rows, so this one would only wait on its row locks. On SQLite,
// another Sweep running at the same time deletes some of the same rows
// first; it only ends this one sooner.
func (d *DB) sweepTable(ctx context.Context, statement string, now time.Time) (int64, error) {
	var total int64
	for {
		var n int64
		err := d.sweepWrite(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, statement, now.Unix(), now.Unix(), sweepBatch, now.Unix())
			if err != nil {
				return err
			}
			n, err = res.RowsAffected()
			return err
		})
		total += n
		if err != nil || n <= int64(sweepBatch) {
			return total, err
		}
	}
}

// sweepWrite runs one of sweepTable's batches: in a transaction holding
// the schema's sweep lock on Postgres, as writeOne does on SQLite.
func (d *DB) sweepWrite(ctx context.Context, fn func(q querier) error) error {
	if d.dialect == SQLite {
		return d.writeOne(ctx, fn)
	}
	return d.write(ctx, func(q querier) error {
		var locked bool
		if err := q.QueryRowContext(ctx, postgresSweepLock).Scan(&locked); err != nil {
			return err
		}
		if !locked {
			return errSweepLocked
		}
		return fn(q)
	})
}
