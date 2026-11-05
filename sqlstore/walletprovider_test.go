package sqlstore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/walletprovider"
	"github.com/idfoundry/oid4vcgo/walletprovider/walletprovidertest"
)

func TestWalletProviderInstanceStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		walletprovidertest.TestInstanceStoreContract(t, func(*testing.T) walletprovider.InstanceStore {
			return e.db().WalletProviderInstances()
		})
	})
}

func TestWalletProviderInstanceKeyStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		walletprovidertest.TestInstanceKeyStoreContract(t, func(*testing.T) walletprovider.InstanceKeyStore {
			return e.db().WalletProviderInstanceKeys()
		})
	})
}

func TestWalletProviderChallengeStoreContract(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		walletprovidertest.TestChallengeStoreContract(t, func(*testing.T) walletprovider.ChallengeStore {
			return e.db().WalletProviderChallenges()
		})
	})
}

func testInstanceKey(thumbprint, instanceID string) walletprovider.InstanceKey {
	return walletprovider.InstanceKey{
		Thumbprint: thumbprint, Key: []byte(`{"kty":"EC"}`), InstanceID: instanceID,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

func testInstance(id string) walletprovider.Instance {
	return walletprovider.Instance{
		ID: id, KeyThumbprint: "tp-" + id, Key: []byte(`{"kty":"EC"}`),
		State: walletprovider.StateActive, CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
}

// Across separate handles, as across processes: of concurrent Creates
// of one instance key, one registers it, and concurrent Updates of one
// instance, each retried on ErrConflict, lose none of their changes.
func TestWalletProviderInstancesAcrossHandles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		const n = 8
		stores := make([]*sqlstore.InstanceStore, n)
		for i := range stores {
			stores[i] = open().WalletProviderInstances()
		}

		errs := make([]error, n)
		var wg sync.WaitGroup
		for i, s := range stores {
			in := testInstance(fmt.Sprintf("id-%d", i))
			in.KeyThumbprint = "one-key"
			wg.Go(func() { errs[i] = s.Create(ctx, in) })
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, walletprovider.ErrExists):
				t.Errorf("concurrent Create: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d concurrent Creates with one key thumbprint succeeded, want 1", won)
		}

		if err := stores[0].Create(ctx, testInstance("counted")); err != nil {
			t.Fatal(err)
		}
		for i, s := range stores {
			wg.Go(func() {
				for {
					cur, err := s.Get(ctx, "counted")
					if err != nil {
						errs[i] = err
						return
					}
					cur.Counter++
					if err = s.Update(ctx, cur); !errors.Is(err, walletprovider.ErrConflict) {
						errs[i] = err
						return
					}
				}
			})
		}
		wg.Wait()
		if err := errors.Join(errs...); err != nil {
			t.Fatalf("concurrent Update: %v", err)
		}
		got, err := stores[n-1].Get(ctx, "counted")
		if err != nil || got.Counter != n || got.Revision != n+1 {
			t.Errorf("after %d concurrent increments: Counter %d, Revision %d, %v; want %d, %d", n, got.Counter, got.Revision, err, n, n+1)
		}
	})
}

// Across separate handles, as across processes: of concurrent Creates
// of one instance key, for different instances, one records it.
func TestWalletProviderInstanceKeysAcrossHandles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		const n = 8
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			s := open().WalletProviderInstanceKeys()
			wg.Go(func() { errs[i] = s.Create(ctx, testInstanceKey("one-key", fmt.Sprintf("id-%d", i))) })
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, walletprovider.ErrExists):
				t.Errorf("concurrent Create: %v", err)
			}
		}
		if won != 1 {
			t.Fatalf("%d concurrent Creates of one instance key succeeded, want 1", won)
		}
	})
}

// An instance key's Key is kept byte for byte, not re-encoded.
func TestWalletProviderInstanceKeyKeepsItsKey(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().WalletProviderInstanceKeys()
		k := testInstanceKey("tp", "a")
		k.Key = []byte("{ \"kty\": \"EC\",\n  \"crv\": \"P-256\" }")
		if err := s.Create(ctx, k); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "tp")
		if err != nil || !bytes.Equal(got.Key, k.Key) {
			t.Fatalf("Get = %q, %v; want the key as stored, %q", got.Key, err, k.Key)
		}
		listed, err := s.List(ctx, "a", "", 10)
		if err != nil || len(listed) != 1 || !bytes.Equal(listed[0].Key, k.Key) {
			t.Fatalf("List = %+v, %v; want the key as stored, %q", listed, err, k.Key)
		}
	})
}

// A thumbprint, instance ID or List cursor no row can hold is no
// instance key, or refused, rather than a database error.
func TestWalletProviderInstanceKeyUnstorableKeys(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().WalletProviderInstanceKeys()
		bad := "a\x00b"
		if _, err := s.Get(ctx, bad); !errors.Is(err, walletprovider.ErrNotFound) {
			t.Errorf("Get(unstorable) = %v, want ErrNotFound", err)
		}
		for _, k := range []walletprovider.InstanceKey{testInstanceKey(bad, "a"), testInstanceKey("tp", bad)} {
			if err := s.Create(ctx, k); err == nil || errors.Is(err, walletprovider.ErrExists) {
				t.Errorf("Create(%q, %q) = %v, want it refused", k.Thumbprint, k.InstanceID, err)
			}
		}
		if _, err := s.List(ctx, bad, "", 10); err == nil {
			t.Error("List(unstorable instance ID) = nil error")
		}
		if _, err := s.List(ctx, "a", bad, 10); err == nil {
			t.Error("List(unstorable cursor) = nil error")
		}
	})
}

// The instance key is kept byte for byte, not re-encoded, and an Update
// can't change the key thumbprint an instance was registered with.
func TestWalletProviderInstanceKeepsItsKey(t *testing.T) {
	forEachSealing(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().WalletProviderInstances()
		in := testInstance("a")
		in.Key = []byte("{ \"kty\": \"EC\",\n  \"crv\": \"P-256\" }")
		if err := s.Create(ctx, in); err != nil {
			t.Fatal(err)
		}
		got, err := s.Get(ctx, "a")
		if err != nil || !bytes.Equal(got.Key, in.Key) {
			t.Fatalf("Get = %q, %v; want the key as stored, %q", got.Key, err, in.Key)
		}

		changed := got
		changed.KeyThumbprint = "another"
		err = s.Update(ctx, changed)
		if err == nil || errors.Is(err, walletprovider.ErrConflict) || errors.Is(err, walletprovider.ErrNotFound) {
			t.Errorf("Update changing the key thumbprint = %v, want it refused", err)
		}
		if after, err := s.Get(ctx, "a"); err != nil || after.Revision != 1 || after.KeyThumbprint != in.KeyThumbprint {
			t.Errorf("after a refused Update: %+v, %v", after, err)
		}
	})
}

// A store that couldn't answer never reports an instance or challenge
// as unknown, nor one as already stored.
func TestWalletProviderStoreOutageIsNotUnknown(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		instances, challenges := d.WalletProviderInstances(), d.WalletProviderChallenges()
		instanceKeys := d.WalletProviderInstanceKeys()
		e.closeAll()
		_, err := instances.Get(ctx, "a")
		requireOutage(t, "Instances.Get", err, walletprovider.ErrNotFound)
		in := testInstance("a")
		in.Revision = 1
		requireOutage(t, "Instances.Update", instances.Update(ctx, in), walletprovider.ErrNotFound)
		requireOutage(t, "Instances.Create", instances.Create(ctx, in), walletprovider.ErrExists)
		if _, err := instances.List(ctx, "", 10); err == nil {
			t.Error("Instances.List on a closed database = nil error")
		}
		_, err = instanceKeys.Get(ctx, "tp")
		requireOutage(t, "InstanceKeys.Get", err, walletprovider.ErrNotFound)
		requireOutage(t, "InstanceKeys.Create", instanceKeys.Create(ctx, testInstanceKey("tp", "a")), walletprovider.ErrExists)
		if _, err := instanceKeys.List(ctx, "a", "", 10); err == nil {
			t.Error("InstanceKeys.List on a closed database = nil error")
		}
		_, err = challenges.Consume(ctx, "c")
		requireOutage(t, "Challenges.Consume", err, walletprovider.ErrNotFound)
		err = challenges.Create(ctx, walletprovider.ChallengeRecord{Value: "c"})
		requireOutage(t, "Challenges.Create", err, walletprovider.ErrExists)
	})
}

// Sweep deletes the challenges past their ExpiresAt, and never an
// instance or instance key.
func TestSweepWalletProviderChallenges(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d := e.db()
		now := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
		challenges := d.WalletProviderChallenges()
		for value, expires := range map[string]time.Time{"old": now.Add(-time.Minute), "new": now.Add(time.Minute)} {
			if err := challenges.Create(ctx, walletprovider.ChallengeRecord{Value: value, Purpose: walletprovider.PurposeHolder, CreatedAt: expires.Add(-5 * time.Minute), ExpiresAt: expires}); err != nil {
				t.Fatal(err)
			}
		}
		in := testInstance("a")
		in.CreatedAt = now.Add(-24 * time.Hour)
		if err := d.WalletProviderInstances().Create(ctx, in); err != nil {
			t.Fatal(err)
		}
		k := testInstanceKey("tp", "a")
		k.CreatedAt = in.CreatedAt
		if err := d.WalletProviderInstanceKeys().Create(ctx, k); err != nil {
			t.Fatal(err)
		}
		if n, err := d.Sweep(ctx, now); err != nil || n != 1 {
			t.Errorf("Sweep = %d, %v; want 1 deleted", n, err)
		}
		if _, err := challenges.Consume(ctx, "old"); !errors.Is(err, walletprovider.ErrNotFound) {
			t.Errorf("an expired challenge survived the sweep: %v", err)
		}
		if _, err := challenges.Consume(ctx, "new"); err != nil {
			t.Errorf("an unexpired challenge was swept: %v", err)
		}
		if _, err := d.WalletProviderInstances().Get(ctx, "a"); err != nil {
			t.Errorf("an instance was swept: %v", err)
		}
		if _, err := d.WalletProviderInstanceKeys().Get(ctx, "tp"); err != nil {
			t.Errorf("an instance key was swept: %v", err)
		}
	})
}

// A record moved to another key is refused, sealed or not: an unsealed
// one names its own key. An instance key moved to another instance is
// refused by List, which finds it under that instance.
func TestWalletProviderRecordsAreBoundToTheirKey(t *testing.T) {
	for name, opts := range map[string]sqlstore.Options{"Unsealed": {}, "Sealed": {Sealer: testSealer(t)}} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			d, raw := openSQLite(t, filepath.Join(t.TempDir(), "store.db"), opts)
			if err := d.Migrate(ctx); err != nil {
				t.Fatal(err)
			}
			if err := d.WalletProviderInstances().Create(ctx, testInstance("a")); err != nil {
				t.Fatal(err)
			}
			if err := d.WalletProviderChallenges().Create(ctx, walletprovider.ChallengeRecord{Value: "a"}); err != nil {
				t.Fatal(err)
			}
			keys := d.WalletProviderInstanceKeys()
			for _, k := range []walletprovider.InstanceKey{testInstanceKey("a", "i"), testInstanceKey("c", "i")} {
				if err := keys.Create(ctx, k); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := raw.ExecContext(ctx, "UPDATE oid4vc_walletprovider_instance_keys SET instance_id = 'j' WHERE id = 'c'"); err != nil {
				t.Fatal(err)
			}
			if _, err := keys.List(ctx, "j", "", 10); !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("List of an instance key moved to another instance = %v, want ErrRecordFormat", err)
			}
			for _, table := range []string{"instances", "instance_keys", "challenges"} {
				if _, err := raw.ExecContext(ctx, "UPDATE oid4vc_walletprovider_"+table+" SET id = 'b' WHERE id = 'a'"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := d.WalletProviderInstances().Get(ctx, "b"); !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("Get of an instance moved to another ID = %v, want ErrRecordFormat", err)
			}
			if _, err := keys.Get(ctx, "b"); !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("Get of an instance key moved to another thumbprint = %v, want ErrRecordFormat", err)
			}
			if _, err := d.WalletProviderChallenges().Consume(ctx, "b"); !errors.Is(err, sqlstore.ErrRecordFormat) {
				t.Errorf("Consume of a challenge moved to another value = %v, want ErrRecordFormat", err)
			}
		})
	}
}

// A database migrated by an earlier release, to version 4, migrates to
// the Wallet Provider tables with its records kept; until then,
// CheckSchema fails and the stores report an error, never an unknown
// instance or challenge.
func TestMigrateAddsWalletProviderTables(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d, err := sqlstore.New(e.location()(), e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlstore.MigrateTo(ctx, d, 4); err != nil {
			t.Fatal(err)
		}
		if err := d.StatusIndices().Reserve(ctx, statusListA, 0); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "0005_walletprovider.sql") {
			t.Errorf("CheckSchema at version 4 = %v, want migration 0005 missing", err)
		}
		_, err = d.WalletProviderInstances().Get(ctx, "a")
		requireOutage(t, "Instances.Get before migration 0005", err, walletprovider.ErrNotFound)
		_, err = d.WalletProviderChallenges().Consume(ctx, "c")
		requireOutage(t, "Challenges.Consume before migration 0005", err, walletprovider.ErrNotFound)

		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err != nil {
			t.Errorf("CheckSchema after Migrate: %v", err)
		}
		if _, err := d.StatusIndices().Status(ctx, statusListA, 0); err != nil {
			t.Errorf("a record from before the migration: %v", err)
		}
		if err := d.WalletProviderInstances().Create(ctx, testInstance("a")); err != nil {
			t.Errorf("Create after migration: %v", err)
		}
	})
}

// A database migrated by an earlier release, to version 5, migrates to
// the instance key table with its records kept; until then,
// CheckSchema fails and the store reports an error, never an unknown
// instance key.
func TestMigrateAddsWalletProviderInstanceKeys(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d, err := sqlstore.New(e.location()(), e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlstore.MigrateTo(ctx, d, 5); err != nil {
			t.Fatal(err)
		}
		if err := d.WalletProviderInstances().Create(ctx, testInstance("a")); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "0006_walletprovider_instance_keys.sql") {
			t.Errorf("CheckSchema at version 5 = %v, want migration 0006 missing", err)
		}
		_, err = d.WalletProviderInstanceKeys().Get(ctx, "tp")
		requireOutage(t, "InstanceKeys.Get before migration 0006", err, walletprovider.ErrNotFound)

		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err != nil {
			t.Errorf("CheckSchema after Migrate: %v", err)
		}
		if _, err := d.WalletProviderInstances().Get(ctx, "a"); err != nil {
			t.Errorf("a record from before the migration: %v", err)
		}
		if err := d.WalletProviderInstanceKeys().Create(ctx, testInstanceKey("tp", "a")); err != nil {
			t.Errorf("Create after migration: %v", err)
		}
	})
}
