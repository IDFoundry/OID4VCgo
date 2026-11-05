package sqlstore

import (
	"context"
	"fmt"
	"time"
)

// Sweep deletes every issuer, verifier and Wallet Provider record that
// expired before now and returns how many it deleted. The stores never
// delete an expired record themselves — each is answered as unknown,
// or refused, by the issuer, verifier or provider once it has expired
// — so run Sweep periodically (every few minutes, say) to keep the
// tables, and the personal data in them, from growing without bound.
//
// What "expired" means for each record:
//   - a c_nonce, pre-authorized code or Credential Offer: its ExpiresAt;
//   - a deferred transaction or notification_id: its ExpiresAt, and
//     never when that's zero. To give a Wallet longer to collect a
//     deferred credential after it lapses, pass an earlier now;
//   - a verifier transaction: its RetainUntil, the earliest a store may
//     delete it, and never when that's zero;
//   - a Wallet Provider's challenge: its ExpiresAt.
//
// Sweep leaves the wallet's tables alone. An expired authorization in
// progress names the instance and DPoP keys it was started with, which
// walletflow deletes with it when it next lists the authorizations
// (Wallet.KeysInUse, which a wallet should call periodically):
// deleting the authorization here would orphan its keys in the
// KeyStore, which can't list them. A wallet's credentials, refresh
// grants, pending deferred credentials and keys have no expiry here
// either: walletflow deletes them itself. Nor does it touch the Status
// List indices StatusIndices records, which are never freed, or a
// Wallet Provider's registered instances, which never expire.
func (d *DB) Sweep(ctx context.Context, now time.Time) (int64, error) {
	// What each table's records say they're good until.
	sweeps := []struct{ table, statement string }{
		{"issuer_nonces", d.sql.nonceSweep},                     // NonceIssuance.ExpiresAt
		{"issuer_pre_authorized_codes", d.sql.pacSweep},         // PreAuthorizedCodeRecord.ExpiresAt
		{"issuer_deferred_transactions", d.sql.deferredTxSweep}, // DeferredTransactionRecord.ExpiresAt; never when zero
		{"issuer_notifications", d.sql.notificationSweep},       // NotificationRecord.ExpiresAt; never when zero
		{"issuer_credential_offers", d.sql.offerSweep},          // CredentialOfferRecord.ExpiresAt
		{"verifier_transactions", d.sql.txSweep},                // Transaction.RetainUntil; never when zero
		{"walletprovider_challenges", d.sql.wpChallengeSweep},   // ChallengeRecord.ExpiresAt
	}
	var total int64
	for _, sw := range sweeps {
		err := d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, sw.statement, now.Unix())
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			total += n
			return err
		})
		if err != nil {
			return total, fmt.Errorf("sqlstore: sweep %s: %w", sw.table, err)
		}
	}
	return total, nil
}
