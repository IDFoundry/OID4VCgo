package sqlstore_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
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
