package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

func TestTransactionStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		t.Run("Unsealed", func(t *testing.T) {
			verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore {
				return e.db().Transactions(verifier.TransactionCodec{})
			})
		})
		t.Run("Sealed", func(t *testing.T) {
			codec := verifier.TransactionCodec{Sealer: testSealer(t)}
			verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore {
				return e.db().Transactions(codec)
			})
		})
	})
}

func TestTransactionStoreDeclaresProductionCapabilities(t *testing.T) {
	c := newSQLiteDB(t, sqlstore.Options{}).Transactions(verifier.TransactionCodec{}).Capabilities()
	if !c.Durable || !c.AtomicUpdate {
		t.Errorf("Capabilities() = %+v, want Durable and AtomicUpdate", c)
	}
}

// A codec without a Sealer takes the DB's, and the store says whether
// it seals.
func TestTransactionStoreSealsWithTheDBsSealer(t *testing.T) {
	ctx := context.Background()
	if newSQLiteDB(t, sqlstore.Options{}).Transactions(verifier.TransactionCodec{}).SealsTransactions() {
		t.Error("a DB and codec without a Sealer: SealsTransactions() = true")
	}
	sealer := testSealer(t)
	path := filepath.Join(t.TempDir(), "store.db")
	d, _ := openSQLite(t, path, sqlstore.Options{Sealer: sealer})
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store := d.Transactions(verifier.TransactionCodec{})
	if !store.SealsTransactions() {
		t.Error("a DB with a Sealer: SealsTransactions() = false")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tx := verifier.Transaction{
		ID: "tx-1", KeyID: "kid-1", Owner: "o", ResponseDecryptionKey: key,
		ExpiresAt: time.Now().Add(time.Hour), Status: verifier.TransactionPending,
	}
	if err := store.Create(ctx, tx); err != nil {
		t.Fatal(err)
	}
	// Sealed with the DB's Sealer: a codec naming it reads the record.
	if _, err := d.Transactions(verifier.TransactionCodec{Sealer: sealer}).Get(ctx, "tx-1"); err != nil {
		t.Errorf("Get with the DB's Sealer: %v", err)
	}
	unsealed, _ := openSQLite(t, path, sqlstore.Options{})
	if _, err := unsealed.Transactions(verifier.TransactionCodec{}).Get(ctx, "tx-1"); !errors.Is(err, sqlstore.ErrRecordFormat) {
		t.Errorf("Get without a Sealer = %v, want ErrRecordFormat: the record is sealed", err)
	}
}

// A transaction sealed under one key isn't read with another, or
// without one.
func TestTransactionStoreRefusesAnotherSealer(t *testing.T) {
	ctx := context.Background()
	d := newSQLiteDB(t, sqlstore.Options{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tx := verifier.Transaction{
		ID: "tx-1", KeyID: "kid-1", Owner: "o", ResponseDecryptionKey: key,
		ExpiresAt: time.Now().Add(time.Hour), Status: verifier.TransactionPending,
	}
	if err := d.Transactions(verifier.TransactionCodec{Sealer: testSealer(t)}).Create(ctx, tx); err != nil {
		t.Fatal(err)
	}
	for name, codec := range map[string]verifier.TransactionCodec{"another key": {Sealer: testSealer(t)}, "no sealer": {}} {
		_, err := d.Transactions(codec).Get(ctx, "tx-1")
		if !errors.Is(err, sqlstore.ErrRecordFormat) || errors.Is(err, verifier.ErrTransactionUnknown) {
			t.Errorf("Get with %s = %v, want ErrRecordFormat", name, err)
		}
	}
}

// An update that leaves the transaction as it was writes nothing: the
// sealed record, sealed afresh by every write, stays byte for byte.
func TestTransactionUpdateSkipsUnchanged(t *testing.T) {
	ctx := context.Background()
	d, db := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), sqlstore.Options{Sealer: testSealer(t)})
	if err := d.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	store := d.Transactions(verifier.TransactionCodec{})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tx := verifier.Transaction{
		ID: "tx-1", KeyID: "kid-1", Owner: "o", ResponseDecryptionKey: key, BrowserBindingHash: []byte{1, 2},
		ExpiresAt: time.Now().Add(time.Hour), Status: verifier.TransactionPending,
	}
	if err := store.Create(ctx, tx); err != nil {
		t.Fatal(err)
	}
	record := func() string {
		t.Helper()
		var data []byte
		if err := db.QueryRowContext(ctx, "SELECT record FROM oid4vc_verifier_transactions WHERE id = ?", "tx-1").Scan(&data); err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	before := record()
	if err := store.Update(ctx, "tx-1", func(*verifier.Transaction) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if record() != before {
		t.Error("an update changing nothing rewrote the record")
	}
	if err := store.Update(ctx, "tx-1", func(tx *verifier.Transaction) error {
		tx.BrowserBindingHash[0] = 9 // in place: the comparison mustn't share it
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if record() == before {
		t.Error("an update changing the record in place didn't write it")
	}
	got, err := store.Get(ctx, "tx-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.BrowserBindingHash[0] != 9 {
		t.Errorf("BrowserBindingHash = %v, want the update's", got.BrowserBindingHash)
	}
}
