package sqlstore

import (
	"context"
	"fmt"
	"time"
)

// sweptTables are the tables whose records Sweep deletes once past
// their sweep_after: what each store's records say they're good until.
var sweptTables = []string{
	"issuer_nonces",                // NonceIssuance.ExpiresAt
	"issuer_pre_authorized_codes",  // PreAuthorizedCodeRecord.ExpiresAt
	"issuer_deferred_transactions", // DeferredTransactionRecord.ExpiresAt; never when zero
	"issuer_notifications",         // NotificationRecord.ExpiresAt; never when zero
	"issuer_credential_offers",     // CredentialOfferRecord.ExpiresAt
}

// Sweep deletes every record that expired before now, from every table
// that has them, and returns how many it deleted. The stores never
// delete an expired record themselves — each is answered as unknown, or
// refused, by the issuer once it has expired — so
// run Sweep periodically (every few minutes, say) to keep the tables,
// and the personal data in them, from growing without bound.
//
// What "expired" means for each record:
//   - a c_nonce, pre-authorized code or Credential Offer: its ExpiresAt;
//   - a deferred transaction or notification_id: its ExpiresAt, and
//     never when that's zero. To give a Wallet longer to collect a
//     deferred credential after it lapses, pass an earlier now.
func (d *DB) Sweep(ctx context.Context, now time.Time) (int64, error) {
	var total int64
	for _, name := range sweptTables {
		err := d.writeOne(ctx, func(q querier) error {
			res, err := q.ExecContext(ctx, d.q("DELETE FROM {"+name+"} WHERE sweep_after < ?"), now.Unix())
			if err != nil {
				return err
			}
			n, err := res.RowsAffected()
			total += n
			return err
		})
		if err != nil {
			return total, fmt.Errorf("sqlstore: sweep %s: %w", name, err)
		}
	}
	return total, nil
}
