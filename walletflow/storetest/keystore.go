package storetest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// purposes are every walletflow.KeyPurpose.
var purposes = []walletflow.KeyPurpose{walletflow.KeyPurposeInstance, walletflow.KeyPurposeDPoP, walletflow.KeyPurposeHolder}

// TestKeyStoreContract exercises factory()'s stores against
// walletflow.KeyStore's guarantees: NewKey creates a P-256 key, for
// every purpose, that signs a SHA-256 digest as an ASN.1 DER ECDSA
// signature; Key finds it again by its ID, the same key; every NewKey's
// key is a new one, with its own ID; a missing key is
// walletflow.ErrNotFound; DeleteKey deletes only that key, and deleting
// a missing one isn't an error; concurrent use is safe; and a cancelled
// context completes the call or fails it with the context's error. It
// doesn't check that keys survive a restart, or what protects them.
// factory must return a fresh, empty store each call.
func TestKeyStoreContract(t *testing.T, factory func() walletflow.KeyStore) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, walletflow.KeyStore)
	}{
		{"NewKeySignsForEveryPurpose", testNewKeySigns},
		{"KeyFindsTheSameKey", testKeyFindsSameKey},
		{"EveryKeyIsNew", testEveryKeyIsNew},
		{"UnknownIsNotFound", testUnknownKey},
		{"DeleteKeyRemovesOnlyThatKey", testDeleteKey},
		{"ConcurrentUse", testConcurrentKeys},
		{"CancelledContext", testCancelledKeys},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, factory()) })
	}
}

func mustNewKey(t *testing.T, s walletflow.KeyStore, purpose walletflow.KeyPurpose) walletflow.Key {
	t.Helper()
	k, err := s.NewKey(context.Background(), purpose)
	if err != nil {
		t.Fatalf("NewKey(%s): %v", purpose, err)
	}
	if k.ID() == "" {
		t.Fatalf("NewKey(%s) returned a key with no ID", purpose)
	}
	return k
}

// checkSigns returns why k isn't a P-256 key whose signatures verify
// under want (k's own public key when nil), or nil.
func checkSigns(k walletflow.Key, want *ecdsa.PublicKey) error {
	pub, ok := k.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("not a P-256 ECDSA key")
	}
	if want == nil {
		want = pub
	} else if !pub.Equal(want) {
		return errors.New("its public key isn't the one NewKey returned")
	}
	digest := sha256.Sum256([]byte("walletflow storetest " + k.ID()))
	sig, err := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(want, digest[:], sig) {
		return errors.New("its signature doesn't verify as ASN.1 DER ECDSA over the digest")
	}
	return nil
}

func testNewKeySigns(t *testing.T, s walletflow.KeyStore) {
	for _, purpose := range purposes {
		if err := checkSigns(mustNewKey(t, s, purpose), nil); err != nil {
			t.Errorf("NewKey(%s): %v", purpose, err)
		}
	}
}

func testKeyFindsSameKey(t *testing.T, s walletflow.KeyStore) {
	for _, purpose := range purposes {
		k := mustNewKey(t, s, purpose)
		got, err := s.Key(context.Background(), k.ID())
		if err != nil {
			t.Fatalf("Key(%s key): %v", purpose, err)
		}
		if got.ID() != k.ID() {
			t.Errorf("Key(%q) returned key %q", k.ID(), got.ID())
		}
		if err := checkSigns(got, k.Public().(*ecdsa.PublicKey)); err != nil {
			t.Errorf("Key(%s key): %v", purpose, err)
		}
	}
}

func testEveryKeyIsNew(t *testing.T, s walletflow.KeyStore) {
	ids, pubs := map[string]bool{}, []*ecdsa.PublicKey{}
	for range 3 {
		for _, purpose := range purposes {
			k := mustNewKey(t, s, purpose)
			pub := k.Public().(*ecdsa.PublicKey)
			if ids[k.ID()] {
				t.Errorf("NewKey(%s) reused ID %q", purpose, k.ID())
			}
			for _, p := range pubs {
				if p.Equal(pub) {
					t.Errorf("NewKey(%s) reused a public key", purpose)
				}
			}
			ids[k.ID()], pubs = true, append(pubs, pub)
		}
	}
}

func testUnknownKey(t *testing.T, s walletflow.KeyStore) {
	mustNewKey(t, s, walletflow.KeyPurposeHolder)
	if _, err := s.Key(context.Background(), "unknown"); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Key(unknown) = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
}

func testDeleteKey(t *testing.T, s walletflow.KeyStore) {
	ctx := context.Background()
	if err := s.DeleteKey(ctx, "unknown"); err != nil {
		t.Errorf("DeleteKey(unknown) = %v, want nil", err)
	}
	gone, kept := mustNewKey(t, s, walletflow.KeyPurposeHolder), mustNewKey(t, s, walletflow.KeyPurposeHolder)
	if err := s.DeleteKey(ctx, gone.ID()); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	if _, err := s.Key(ctx, gone.ID()); !errors.Is(err, walletflow.ErrNotFound) {
		t.Errorf("Key of a deleted key = %v, want an error wrapping walletflow.ErrNotFound", err)
	}
	if err := s.DeleteKey(ctx, gone.ID()); err != nil {
		t.Errorf("DeleteKey again = %v, want nil", err)
	}
	k, err := s.Key(ctx, kept.ID())
	if err != nil {
		t.Fatalf("Key of the key not deleted: %v", err)
	}
	if err := checkSigns(k, kept.Public().(*ecdsa.PublicKey)); err != nil {
		t.Errorf("the key not deleted: %v", err)
	}
}

func testConcurrentKeys(t *testing.T, s walletflow.KeyStore) {
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := map[string]bool{}
	var problems []error
	report := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		problems = append(problems, err)
	}
	for i := range contractConcurrency {
		wg.Go(func() {
			k, err := s.NewKey(ctx, purposes[i%len(purposes)])
			if err != nil {
				report(err)
				return
			}
			mu.Lock()
			dup := ids[k.ID()]
			ids[k.ID()] = true
			mu.Unlock()
			if dup {
				report(errors.New("two concurrent NewKeys returned one ID"))
			}
			found, err := s.Key(ctx, k.ID())
			if err == nil {
				err = checkSigns(found, k.Public().(*ecdsa.PublicKey))
			}
			if err != nil {
				report(err)
			}
			if i%2 == 0 {
				if err := s.DeleteKey(ctx, k.ID()); err != nil {
					report(err)
				}
			}
		})
	}
	wg.Wait()
	for _, err := range problems {
		t.Errorf("concurrent use: %v", err)
	}
}

func testCancelledKeys(t *testing.T, s walletflow.KeyStore) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	k, err := s.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		expectCanceled(t, "NewKey", err)
		k = mustNewKey(t, s, walletflow.KeyPurposeHolder)
	} else if err := checkSigns(k, nil); err != nil {
		t.Errorf("NewKey with a cancelled context: %v", err)
	}
	if found, err := s.Key(ctx, k.ID()); err != nil {
		expectCanceled(t, "Key", err)
	} else if err := checkSigns(found, k.Public().(*ecdsa.PublicKey)); err != nil {
		t.Errorf("Key with a cancelled context: %v", err)
	}
	err = s.DeleteKey(ctx, k.ID())
	_, after := s.Key(context.Background(), k.ID())
	if err != nil {
		expectCanceled(t, "DeleteKey", err)
		if after != nil {
			t.Errorf("Key after a failed DeleteKey = %v, want the key kept", after)
		}
	} else if !errors.Is(after, walletflow.ErrNotFound) {
		t.Errorf("Key after DeleteKey with a cancelled context = %v, want walletflow.ErrNotFound", after)
	}
}
