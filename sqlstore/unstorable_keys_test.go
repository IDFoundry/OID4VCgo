package sqlstore_test

import (
	"context"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// A key PostgreSQL's text columns can't hold — invalid UTF-8, or one
// with a NUL byte — is a key no store holds, on either dialect: a
// lookup by one answers not found, never the database's error, and a
// write refuses it.
func TestUnstorableKeysAreNotFound(t *testing.T) {
	for name, key := range map[string]string{"invalid UTF-8": "k\xff\xfe", "NUL": "k\x00k"} {
		t.Run(name, func(t *testing.T) {
			forEachDialect(t, func(t *testing.T, e *env) {
				e.opts = sqlstore.Options{Sealer: testSealer(t)}
				testUnstorableKey(t, e.db(), key)
			})
		})
	}
}

func testUnstorableKey(t *testing.T, d *sqlstore.DB, key string) {
	ctx := context.Background()
	want := func(what string, err, target error) {
		t.Helper()
		if !errors.Is(err, target) {
			t.Errorf("%s: %v, want %v", what, err, target)
		}
	}

	_, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: key})
	want("Nonces.Consume", err, issuer.ErrNonceUnknown)
	_, err = d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "n", Owner: key})
	want("Nonces.Consume by owner", err, issuer.ErrNonceUnknown)
	_, _, err = d.PreAuthorizedCodes().Consume(ctx, key, "", 0, nil)
	want("PreAuthorizedCodes.Consume", err, issuer.ErrPreAuthorizedCodeUnknown)
	want("PreAuthorizedCodes.Invalidate", d.PreAuthorizedCodes().Invalidate(ctx, key), nil)
	_, err = d.DeferredTransactions().Get(ctx, key)
	want("DeferredTransactions.Get", err, issuer.ErrDeferredTransactionUnknown)
	want("DeferredTransactions.Invalidate", d.DeferredTransactions().Invalidate(ctx, key), issuer.ErrDeferredTransactionUnknown)
	want("DeferredTransactions.Update", d.DeferredTransactions().Update(ctx, key, func(*issuer.DeferredTransactionRecord) error { return nil }), issuer.ErrDeferredTransactionUnknown)
	_, err = d.Notifications().Get(ctx, key)
	want("Notifications.Get", err, issuer.ErrNotificationIDUnknown)
	_, err = d.CredentialOffers().Get(ctx, key)
	want("CredentialOffers.Get", err, sqlstore.ErrNotFound)

	txs := d.Transactions(verifier.TransactionCodec{})
	_, err = txs.Get(ctx, key)
	want("Transactions.Get", err, verifier.ErrTransactionUnknown)
	want("Transactions.Update", txs.Update(ctx, key, func(*verifier.Transaction) error { return nil }), verifier.ErrTransactionUnknown)
	_, err = txs.IDByKeyID(ctx, key)
	want("Transactions.IDByKeyID", err, verifier.ErrTransactionUnknown)
	_, err = txs.IDByResponseCode(ctx, key)
	want("Transactions.IDByResponseCode", err, verifier.ErrTransactionUnknown)

	_, err = d.Credentials().Get(ctx, key)
	want("Credentials.Get", err, walletflow.ErrNotFound)
	want("Credentials.Update", d.Credentials().Update(ctx, key, func(*walletflow.StoredCredential) error { return nil }), walletflow.ErrNotFound)
	want("Credentials.Delete", d.Credentials().Delete(ctx, key), nil)
	_, err = d.Authorizations().GetAuthorization(ctx, key)
	want("Authorizations.GetAuthorization", err, walletflow.ErrNotFound)
	_, err = d.Authorizations().ConsumeAuthorization(ctx, key)
	want("Authorizations.ConsumeAuthorization", err, walletflow.ErrNotFound)
	want("Authorizations.DeleteAuthorization", d.Authorizations().DeleteAuthorization(ctx, key), nil)
	_, err = d.Grants().GetGrant(ctx, key)
	want("Grants.GetGrant", err, walletflow.ErrNotFound)
	want("Grants.UpdateGrant", d.Grants().UpdateGrant(ctx, key, func(*walletflow.RefreshGrant) error { return nil }), walletflow.ErrNotFound)
	want("Grants.DeleteGrant", d.Grants().DeleteGrant(ctx, key), nil)
	want("Deferred.DeleteDeferred", d.Deferred().DeleteDeferred(ctx, key), nil)
	ks, err := d.Keys()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ks.Key(ctx, key)
	want("Keys.Key", err, walletflow.ErrNotFound)
	want("Keys.DeleteKey", ks.DeleteKey(ctx, key), nil)

	// Writes refuse it, on SQLite as on Postgres.
	for what, err := range map[string]error{
		"Notifications.Issue":             d.Notifications().Issue(ctx, key, issuer.NotificationRecord{}),
		"Credentials.Put":                 d.Credentials().Put(ctx, walletflow.StoredCredential{ID: key}),
		"Authorizations.PutAuthorization": d.Authorizations().PutAuthorization(ctx, walletflow.PendingAuthorization{State: key}),
	} {
		if err == nil {
			t.Errorf("%s = nil error, want a refusal", what)
		}
	}
}
