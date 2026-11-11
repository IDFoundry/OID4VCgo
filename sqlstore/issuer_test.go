package sqlstore_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/issuer/issuertest"
	"github.com/idfoundry/oid4vcgo/sqlstore"
)

func TestNonceStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		issuertest.TestNonceStoreContract(t, func() issuer.NonceStore { return e.db().Nonces() })
		issuertest.TestNonceSpenderContract(t, func() issuer.NonceSpender { return e.db().Nonces() })
	})
}

func TestPreAuthorizedCodeStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		issuertest.TestPreAuthorizedCodeStoreContract(t, func() issuer.PreAuthorizedCodeStore { return e.db().PreAuthorizedCodes() })
	})
}

func TestDeferredTransactionStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		issuertest.TestDeferredTransactionStoreContract(t, func(t *testing.T, id string, record issuer.DeferredTransactionRecord) issuer.DeferredTransactionStore {
			s := e.db().DeferredTransactions()
			if err := s.Create(context.Background(), id, record); err != nil {
				t.Fatalf("Create: %v", err)
			}
			return s
		})
	})
}

func TestNotificationStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		issuertest.TestNotificationStoreContract(t, func() issuer.NotificationStore { return e.db().Notifications() })
	})
}

func TestCredentialOfferStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		issuertest.TestCredentialOfferStoreContract(t, func() issuer.CredentialOfferStore { return e.db().CredentialOffers() })
	})
}

// The issuer stores declare what AssuranceProduction requires of them.
func TestIssuerStoresDeclareProductionCapabilities(t *testing.T) {
	d := newSQLiteDB(t, sqlstore.Options{})
	for name, s := range map[string]issuer.StoreAssurance{
		"Nonces": d.Nonces(), "PreAuthorizedCodes": d.PreAuthorizedCodes(), "DeferredTransactions": d.DeferredTransactions(),
		"Notifications": d.Notifications(), "CredentialOffers": d.CredentialOffers(),
	} {
		if c := s.Capabilities(); !c.Durable || !c.AtomicConsume {
			t.Errorf("%s.Capabilities() = %+v, want Durable and AtomicConsume", name, c)
		}
	}
}

// The issuer stores say they seal their records (sealing.Store's
// SealsRecords) exactly when the DB has a Sealer.
func TestIssuerStoresDeclareSealing(t *testing.T) {
	type sealingStore interface{ SealsRecords() bool }
	for _, sealed := range []bool{false, true} {
		opts := sqlstore.Options{}
		if sealed {
			opts.Sealer = testSealer(t)
		}
		d := newSQLiteDB(t, opts)
		for name, s := range map[string]sealingStore{
			"Nonces": d.Nonces(), "PreAuthorizedCodes": d.PreAuthorizedCodes(), "DeferredTransactions": d.DeferredTransactions(),
			"Notifications": d.Notifications(), "CredentialOffers": d.CredentialOffers(),
		} {
			if got := s.SealsRecords(); got != sealed {
				t.Errorf("with a Sealer %t: %s.SealsRecords() = %t", sealed, name, got)
			}
		}
	}
}

// Every field of every issuer record survives the store, an issued
// Credential and a whole Credential Offer included.
func TestIssuerRecordsRoundTrip(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		exp := time.Date(2026, 10, 30, 12, 0, 0, 123456789, time.UTC)

		pac := issuer.PreAuthorizedCodeRecord{
			Owner: "https://issuer.example.com", TxCodeHash: "hash", Scopes: []string{"a", "b"},
			CredentialConfigurationIDs: []string{"pid"}, ExpiresAt: exp, Subject: "subject",
		}
		if err := d.PreAuthorizedCodes().Issue(ctx, "code-hash", pac); err != nil {
			t.Fatal(err)
		}
		got, _, err := d.PreAuthorizedCodes().Consume(ctx, "code-hash", "hash", 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		requireEqualJSON(t, "pre-authorized code", got, pac)

		offer := issuer.CredentialOfferRecord{
			Reference: "ref", ExpiresAt: exp,
			Offer: oid4vci.CredentialOffer{CredentialIssuer: "https://issuer.example.com", CredentialConfigurationIDs: []string{"pid"}},
		}
		if err := d.CredentialOffers().Store(ctx, offer); err != nil {
			t.Fatal(err)
		}
		gotOffer, err := d.CredentialOffers().Get(ctx, "ref")
		if err != nil {
			t.Fatal(err)
		}
		requireEqualJSON(t, "credential offer", gotOffer, offer)
		if _, err := d.CredentialOffers().Get(ctx, "other"); !errors.Is(err, sqlstore.ErrNotFound) {
			t.Errorf("Get of an unknown offer: %v, want ErrNotFound", err)
		}

		notification := issuer.NotificationRecord{Owner: "o", ClientID: "c", Subject: "s", ExpiresAt: exp}
		if err := d.Notifications().Issue(ctx, "n", notification); err != nil {
			t.Fatal(err)
		}
		gotNotification, err := d.Notifications().Get(ctx, "n")
		if err != nil {
			t.Fatal(err)
		}
		requireEqualJSON(t, "notification", gotNotification, notification)

		deferred := issuer.DeferredTransactionRecord{
			Owner: "o", ClientID: "c", Subject: "s", Status: issuer.DeferredTransactionIssued,
			Credentials: []oid4vci.IssuedCredential{{Credential: "credential"}}, NotificationID: "n",
			CredentialConfigurationID: "pid", BindingKeys: []json.RawMessage{json.RawMessage(`{"kty":"EC"}`)}, ExpiresAt: exp,
			KeyAttestations: []string{"ka"}, ProofKeyHeaders: []json.RawMessage{json.RawMessage(`{"kid":"k"}`)}, Reference: "r",
		}
		if err := d.DeferredTransactions().Create(ctx, "txn", deferred); err != nil {
			t.Fatal(err)
		}
		gotDeferred, err := d.DeferredTransactions().Get(ctx, "txn")
		if err != nil {
			t.Fatal(err)
		}
		requireEqualJSON(t, "deferred transaction", gotDeferred, deferred)
	})
}

// A store outage is never reported as an unknown record (S-19): with
// the database closed, every lookup fails with another error.
func TestIssuerStoreOutageIsNotUnknown(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		e.closeAll()
		_, err := d.Nonces().Consume(ctx, issuer.NonceConsumption{Nonce: "n"})
		requireOutage(t, "Nonces.Consume", err, issuer.ErrNonceUnknown)
		_, _, err = d.PreAuthorizedCodes().Consume(ctx, "c", "", 0, nil)
		requireOutage(t, "PreAuthorizedCodes.Consume", err, issuer.ErrPreAuthorizedCodeUnknown)
		_, err = d.DeferredTransactions().Get(ctx, "t")
		requireOutage(t, "DeferredTransactions.Get", err, issuer.ErrDeferredTransactionUnknown)
		err = d.DeferredTransactions().Invalidate(ctx, "t")
		requireOutage(t, "DeferredTransactions.Invalidate", err, issuer.ErrDeferredTransactionUnknown)
		err = d.DeferredTransactions().Update(ctx, "t", func(*issuer.DeferredTransactionRecord) error { return nil })
		requireOutage(t, "DeferredTransactions.Update", err, issuer.ErrDeferredTransactionUnknown)
		_, err = d.Notifications().Get(ctx, "n")
		requireOutage(t, "Notifications.Get", err, issuer.ErrNotificationIDUnknown)
		_, err = d.CredentialOffers().Get(ctx, "r")
		requireOutage(t, "CredentialOffers.Get", err, sqlstore.ErrNotFound)
	})
}

func requireOutage(t *testing.T, call string, err, unknown error) {
	t.Helper()
	if err == nil || errors.Is(err, unknown) {
		t.Errorf("%s on a closed database = %v, want an error other than %v", call, err, unknown)
	}
}

// A pre-authorized code's tx_code_hash column, which a Sealer leaves
// readable, must be its sealed record's: one changed in the database is
// refused as an unreadable record, never accepted or counted as a wrong
// guess, and the code survives the refusal.
func TestPreAuthorizedCodeTxCodeColumnMustMatchRecord(t *testing.T) {
	ctx := context.Background()
	d, db := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), sqlstore.Options{Sealer: testSealer(t)})
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	codes := d.PreAuthorizedCodes()
	for name, column := range map[string]string{"cleared": "", "replaced": "forged"} {
		t.Run(name, func(t *testing.T) {
			code := "code-" + name
			if err := codes.Issue(ctx, code, issuer.PreAuthorizedCodeRecord{TxCodeHash: "hash", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			if _, err := db.ExecContext(ctx, "UPDATE oid4vc_issuer_pre_authorized_codes SET tx_code_hash = ? WHERE id = ?", column, code); err != nil {
				t.Fatal(err)
			}
			_, _, err := codes.Consume(ctx, code, column, 0, func(issuer.PreAuthorizedCodeRecord) error {
				t.Error("accept was called for an altered code")
				return nil
			})
			if !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("Consume of an altered code = %v, want ErrRecordFormat", err)
			}
			// Still there: the refusal rolled back.
			_, _, err = codes.Consume(ctx, code, column, 0, nil)
			if !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("second Consume = %v, want ErrRecordFormat", err)
			}
		})
	}
}

// The wrong tx_code guesses a code has had count against the limit of
// each Consume, even one lower than when they were made: at it, the
// code is invalidated, the right tx_code refused. The guess reaching
// the limit invalidates it too.
func TestPreAuthorizedCodeTxCodeAttemptLimit(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		codes := e.db().PreAuthorizedCodes()
		issue := func(code string) {
			t.Helper()
			if err := codes.Issue(ctx, code, issuer.PreAuthorizedCodeRecord{TxCodeHash: "right", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
		guess := func(code, txCodeHash string, maxAttempts int, want error) {
			t.Helper()
			if _, _, err := codes.Consume(ctx, code, txCodeHash, maxAttempts, nil); !errors.Is(err, want) {
				t.Errorf("Consume(%s, %s, max %d) = %v, want %v", code, txCodeHash, maxAttempts, err, want)
			}
		}

		issue("lowered")
		guess("lowered", "wrong", 5, issuer.ErrWrongTxCode)
		guess("lowered", "wrong", 5, issuer.ErrWrongTxCode)
		guess("lowered", "right", 2, issuer.ErrTooManyTxCodeAttempts)
		guess("lowered", "right", 5, issuer.ErrPreAuthorizedCodeUnknown)

		issue("reached")
		guess("reached", "wrong", 2, issuer.ErrWrongTxCode)
		guess("reached", "wrong", 2, issuer.ErrWrongTxCode)
		guess("reached", "right", 2, issuer.ErrPreAuthorizedCodeUnknown)
	})
}

// A sealed record is bound to its table: one copied into another
// table, under the same key, is refused.
func TestSealedIssuerRecordsAreBoundToTheirTable(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		e.opts.Sealer = testSealer(t)
		d, raw := e.raw()
		if err := d.Notifications().Issue(ctx, "id", issuer.NotificationRecord{Owner: "o", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.ExecContext(ctx, "INSERT INTO oid4vc_issuer_deferred_transactions (id, owner, sweep_after, record) SELECT id, owner, sweep_after, record FROM oid4vc_issuer_notifications WHERE id = 'id'"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.DeferredTransactions().Get(ctx, "id"); !errors.Is(err, sqlstore.ErrRecordFormat) {
			t.Errorf("Get of a notification's record copied into deferred transactions = %v, want ErrRecordFormat", err)
		}
	})
}
