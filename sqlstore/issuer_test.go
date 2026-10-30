package sqlstore_test

import (
	"context"
	"encoding/json"
	"errors"
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
