package walletprovidertest

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// TestInstanceStoreContract checks that the stores newStore returns
// behave as walletprovider.InstanceStore requires. newStore returns a
// new, empty store each time it's called.
func TestInstanceStoreContract(t *testing.T, newStore func(t *testing.T) walletprovider.InstanceStore) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, walletprovider.InstanceStore)
	}{
		{"GetUnknownIsNotFound", instanceGetUnknown},
		{"CreateThenGet", instanceCreateThenGet},
		{"CreateDuplicateIsExists", instanceCreateDuplicate},
		{"CreateDuplicateKeyIsExists", instanceCreateDuplicateKey},
		{"CreateDuplicateCredentialIsExists", instanceCreateDuplicateCredential},
		{"ConcurrentCreatesOfOneCredential", instanceConcurrentCreatesOfOneCredential},
		{"UpdateComparesRevision", instanceUpdateComparesRevision},
		{"UpdateUnknownIsNotFound", instanceUpdateUnknown},
		{"ConcurrentUpdatesLoseNothing", instanceConcurrentUpdates},
		{"ListPagesInIDOrder", instanceListPages},
		{"ReturnedRecordsAreCopies", instanceCopies},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

// sampleInstance is a record with every field set, its times in UTC at
// whole seconds so a store may keep them at that precision.
func sampleInstance(id string) walletprovider.Instance {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	return walletprovider.Instance{
		ID: id, KeyThumbprint: "tp-" + id, Key: []byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`),
		Evidence: walletprovider.EvidenceSummary{
			Kind: "android-key", Platform: walletprovider.PlatformAndroid,
			SecurityLevel: walletprovider.SecurityLevelStrongBox, Binding: walletprovider.KeyBindingAttested,
			AppID: "com.example.wallet", AppVersion: 42, BootState: walletprovider.BootStateVerified, DeviceLocked: true,
		},
		Credential: []byte{1, 2, 3}, CredentialID: "cred-" + id, Counter: 7,
		State: walletprovider.StateSuspended, Reason: "lost device",
		CreatedAt: at, LastSeenAt: at.Add(time.Hour),
		WalletAttestations: 3, KeyAttestations: 5,
	}
}

func mustCreate(t *testing.T, s walletprovider.InstanceStore, in walletprovider.Instance) {
	t.Helper()
	if err := s.Create(context.Background(), in); err != nil {
		t.Fatalf("Create(%q): %v", in.ID, err)
	}
}

func mustGet(t *testing.T, s walletprovider.InstanceStore, id string) walletprovider.Instance {
	t.Helper()
	in, err := s.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%q): %v", id, err)
	}
	return in
}

// expectInstance compares got with want, times by instant.
func expectInstance(t *testing.T, what string, got, want walletprovider.Instance) {
	t.Helper()
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.LastSeenAt.Equal(want.LastSeenAt) {
		t.Fatalf("%s: times are %v, %v; want %v, %v", what, got.CreatedAt, got.LastSeenAt, want.CreatedAt, want.LastSeenAt)
	}
	got.CreatedAt, got.LastSeenAt = want.CreatedAt, want.LastSeenAt
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s:\n got  %+v\n want %+v", what, got, want)
	}
}

func instanceGetUnknown(t *testing.T, s walletprovider.InstanceStore) {
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get(unknown) = %v, want ErrNotFound", err)
	}
}

func instanceCreateThenGet(t *testing.T, s walletprovider.InstanceStore) {
	in := sampleInstance("a")
	in.Revision = 99 // Create ignores it
	mustCreate(t, s, in)
	in.Revision = 1
	expectInstance(t, "after Create", mustGet(t, s, "a"), in)
}

func instanceCreateDuplicate(t *testing.T, s walletprovider.InstanceStore) {
	in := sampleInstance("a")
	mustCreate(t, s, in)
	other := sampleInstance("a")
	other.Reason = "other"
	if err := s.Create(context.Background(), other); !errors.Is(err, walletprovider.ErrExists) {
		t.Fatalf("Create(duplicate) = %v, want ErrExists", err)
	}
	in.Revision = 1
	expectInstance(t, "after a duplicate Create", mustGet(t, s, "a"), in)
}

func instanceCreateDuplicateKey(t *testing.T, s walletprovider.InstanceStore) {
	mustCreate(t, s, sampleInstance("a"))
	other := sampleInstance("b")
	other.KeyThumbprint = "tp-a"
	if err := s.Create(context.Background(), other); !errors.Is(err, walletprovider.ErrExists) {
		t.Fatalf("Create(another instance with the same key thumbprint) = %v, want ErrExists", err)
	}
	if _, err := s.Get(context.Background(), "b"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get after a refused Create = %v, want ErrNotFound", err)
	}
}

// instanceCreateDuplicateCredential: an instance whose CredentialID
// another has isn't stored; instances without one don't conflict.
func instanceCreateDuplicateCredential(t *testing.T, s walletprovider.InstanceStore) {
	mustCreate(t, s, sampleInstance("a"))
	other := sampleInstance("b")
	other.CredentialID = "cred-a"
	if err := s.Create(context.Background(), other); !errors.Is(err, walletprovider.ErrExists) {
		t.Fatalf("Create(another instance with the same credential ID) = %v, want ErrExists", err)
	}
	if _, err := s.Get(context.Background(), "b"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get after a refused Create = %v, want ErrNotFound", err)
	}
	for _, id := range []string{"c", "d"} {
		in := sampleInstance(id)
		in.CredentialID = ""
		mustCreate(t, s, in)
		if got := mustGet(t, s, id); got.CredentialID != "" {
			t.Fatalf("Get(%q).CredentialID = %q, want empty", id, got.CredentialID)
		}
	}
}

// instanceConcurrentCreatesOfOneCredential: of concurrent Creates of
// instances with one CredentialID, exactly one stores its instance.
func instanceConcurrentCreatesOfOneCredential(t *testing.T, s walletprovider.InstanceStore) {
	const workers = 8
	errs := make([]error, workers)
	var wg sync.WaitGroup
	for i := range workers {
		in := sampleInstance(fmt.Sprintf("id-%d", i))
		in.CredentialID = "one-credential"
		wg.Go(func() { errs[i] = s.Create(context.Background(), in) })
	}
	wg.Wait()
	won := 0
	for i, err := range errs {
		switch {
		case err == nil:
			won++
		case !errors.Is(err, walletprovider.ErrExists):
			t.Fatalf("Create(id-%d): %v, want nil or ErrExists", i, err)
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent Creates of one credential stored it, want 1", won, workers)
	}
	page, err := s.List(context.Background(), "", workers+1)
	if err != nil || len(page) != 1 {
		t.Fatalf("List after concurrent Creates = %d instances, %v; want 1", len(page), err)
	}
}

func instanceUpdateComparesRevision(t *testing.T, s walletprovider.InstanceStore) {
	mustCreate(t, s, sampleInstance("a"))
	in := mustGet(t, s, "a")
	in.State, in.Reason, in.Counter = walletprovider.StateRevoked, "fraud", 8
	if err := s.Update(context.Background(), in); err != nil {
		t.Fatalf("Update: %v", err)
	}
	want := in
	want.Revision = 2
	expectInstance(t, "after Update", mustGet(t, s, "a"), want)

	stale := in // still Revision 1
	stale.Reason = "stale"
	if err := s.Update(context.Background(), stale); !errors.Is(err, walletprovider.ErrConflict) {
		t.Fatalf("Update(stale revision) = %v, want ErrConflict", err)
	}
	expectInstance(t, "after a stale Update", mustGet(t, s, "a"), want)
}

func instanceUpdateUnknown(t *testing.T, s walletprovider.InstanceStore) {
	in := sampleInstance("nope")
	in.Revision = 1
	if err := s.Update(context.Background(), in); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Update(unknown) = %v, want ErrNotFound", err)
	}
}

func instanceConcurrentUpdates(t *testing.T, s walletprovider.InstanceStore) {
	in := sampleInstance("a")
	in.Counter = 0
	mustCreate(t, s, in)
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				cur, err := s.Get(context.Background(), "a")
				if err != nil {
					errs <- err
					return
				}
				cur.Counter++
				switch err := s.Update(context.Background(), cur); {
				case err == nil:
					return
				case !errors.Is(err, walletprovider.ErrConflict):
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Update: %v", err)
	}
	got := mustGet(t, s, "a")
	if got.Counter != workers || got.Revision != workers+1 {
		t.Fatalf("after %d concurrent increments: Counter %d, Revision %d; want %d, %d", workers, got.Counter, got.Revision, workers, workers+1)
	}
}

func instanceListPages(t *testing.T, s walletprovider.InstanceStore) {
	const n = 7
	for i := n - 1; i >= 0; i-- {
		mustCreate(t, s, sampleInstance(fmt.Sprintf("id-%02d", i)))
	}
	var seen []string
	after := ""
	for range n + 1 {
		page, err := s.List(context.Background(), after, 3)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(page) > 3 {
			t.Fatalf("List(limit 3) returned %d", len(page))
		}
		for _, in := range page {
			seen = append(seen, in.ID)
		}
		if len(page) < 3 {
			break
		}
		after = page[len(page)-1].ID
	}
	want := []string{"id-00", "id-01", "id-02", "id-03", "id-04", "id-05", "id-06"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("paging through List saw %v, want %v", seen, want)
	}
}

func instanceCopies(t *testing.T, s walletprovider.InstanceStore) {
	in := sampleInstance("a")
	mustCreate(t, s, in)
	in.Key[0], in.Credential[0] = 'X', 9 // the caller's copy, after Create
	got := mustGet(t, s, "a")
	got.Key[1], got.Credential[1] = 'X', 9 // a returned copy
	again := mustGet(t, s, "a")
	if again.Key[0] == 'X' || again.Key[1] == 'X' || again.Credential[0] == 9 || again.Credential[1] == 9 {
		t.Fatalf("the stored record shares memory with the caller's: %s %v", again.Key, again.Credential)
	}
}

// TestInstanceKeyStoreContract checks that the stores newStore returns
// behave as walletprovider.InstanceKeyStore requires. newStore returns
// a new, empty store each time it's called.
func TestInstanceKeyStoreContract(t *testing.T, newStore func(t *testing.T) walletprovider.InstanceKeyStore) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, walletprovider.InstanceKeyStore)
	}{
		{"GetUnknownIsNotFound", instanceKeyGetUnknown},
		{"CreateThenGet", instanceKeyCreateThenGet},
		{"CreateDuplicateIsExists", instanceKeyCreateDuplicate},
		{"ConcurrentCreatesSucceedOnce", instanceKeyConcurrentCreates},
		{"UpdateComparesRevision", instanceKeyUpdateComparesRevision},
		{"UpdateUnknownIsNotFound", instanceKeyUpdateUnknown},
		{"UpdateKeepsTheInstance", instanceKeyUpdateKeepsInstance},
		{"ConcurrentUpdatesLoseNothing", instanceKeyConcurrentUpdates},
		{"ListPagesOneInstanceInThumbprintOrder", instanceKeyListPages},
		{"ReturnedRecordsAreCopies", instanceKeyCopies},
		{"ListUnretainedPagesKeysWithoutRetainUntil", instanceKeyListUnretained},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

// sampleInstanceKey is a record with every field set, its times in UTC
// at whole seconds so a store may keep them at that precision.
func sampleInstanceKey(thumbprint, instanceID string) walletprovider.InstanceKey {
	created := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	return walletprovider.InstanceKey{
		Thumbprint: thumbprint, Key: []byte(`{"kty":"EC","crv":"P-256","x":"x","y":"y"}`), InstanceID: instanceID,
		Status:         statuslist.StatusListRef{Idx: 1234, URI: "https://provider.example/status/1762300800/0"},
		PreviousStatus: statuslist.StatusListRef{Idx: 77, URI: "https://provider.example/status/1761696000/3"},
		SecurityLevel:  walletprovider.SecurityLevelStrongBox, Binding: walletprovider.KeyBindingAttested,
		CreatedAt: created, RetainUntil: created.Add(90 * 24 * time.Hour),
	}
}

func mustCreateInstanceKey(t *testing.T, s walletprovider.InstanceKeyStore, k walletprovider.InstanceKey) {
	t.Helper()
	if err := s.Create(context.Background(), k); err != nil {
		t.Fatalf("Create(%q): %v", k.Thumbprint, err)
	}
}

// expectInstanceKey reads the record with want's thumbprint and
// compares it with want, its times by instant.
func expectInstanceKey(t *testing.T, s walletprovider.InstanceKeyStore, what string, want walletprovider.InstanceKey) {
	t.Helper()
	got, err := s.Get(context.Background(), want.Thumbprint)
	if err != nil {
		t.Fatalf("%s: Get(%q): %v", what, want.Thumbprint, err)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || !got.RetainUntil.Equal(want.RetainUntil) {
		t.Fatalf("%s: times are %v, %v; want %v, %v", what, got.CreatedAt, got.RetainUntil, want.CreatedAt, want.RetainUntil)
	}
	got.CreatedAt, got.RetainUntil = want.CreatedAt, want.RetainUntil
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%s:\n got  %+v\n want %+v", what, got, want)
	}
}

func instanceKeyGetUnknown(t *testing.T, s walletprovider.InstanceKeyStore) {
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Get(unknown) = %v, want ErrNotFound", err)
	}
}

func instanceKeyCreateThenGet(t *testing.T, s walletprovider.InstanceKeyStore) {
	k := sampleInstanceKey("tp-1", "a")
	k.Revision = 99 // Create ignores it
	mustCreateInstanceKey(t, s, k)
	k.Revision = 1
	expectInstanceKey(t, s, "after Create", k)
}

func instanceKeyCreateDuplicate(t *testing.T, s walletprovider.InstanceKeyStore) {
	k := sampleInstanceKey("tp-1", "a")
	mustCreateInstanceKey(t, s, k)
	k.Revision = 1
	// One key belongs to one instance: the same thumbprint is refused
	// for another instance too.
	for _, instanceID := range []string{"a", "b"} {
		other := sampleInstanceKey("tp-1", instanceID)
		other.Status.Idx = 99
		if err := s.Create(context.Background(), other); !errors.Is(err, walletprovider.ErrExists) {
			t.Fatalf("Create(duplicate thumbprint, instance %q) = %v, want ErrExists", instanceID, err)
		}
	}
	expectInstanceKey(t, s, "after a duplicate Create", k)
}

func instanceKeyConcurrentCreates(t *testing.T, s walletprovider.InstanceKeyStore) {
	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	created := 0
	var unexpected []error
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k := sampleInstanceKey("tp-1", fmt.Sprintf("instance-%d", i))
			err := s.Create(context.Background(), k)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case !errors.Is(err, walletprovider.ErrExists):
				unexpected = append(unexpected, err)
			}
		}()
	}
	wg.Wait()
	if len(unexpected) > 0 {
		t.Fatalf("concurrent Create: %v", unexpected)
	}
	if created != 1 {
		t.Fatalf("%d concurrent Creates of one thumbprint succeeded, want 1", created)
	}
}

func mustGetInstanceKey(t *testing.T, s walletprovider.InstanceKeyStore, thumbprint string) walletprovider.InstanceKey {
	t.Helper()
	k, err := s.Get(context.Background(), thumbprint)
	if err != nil {
		t.Fatalf("Get(%q): %v", thumbprint, err)
	}
	return k
}

func instanceKeyUpdateComparesRevision(t *testing.T, s walletprovider.InstanceKeyStore) {
	mustCreateInstanceKey(t, s, sampleInstanceKey("tp-1", "a"))
	k := mustGetInstanceKey(t, s, "tp-1")
	k.PreviousStatus, k.Status = k.Status, statuslist.StatusListRef{Idx: 9, URI: "https://provider.example/status/1762905600/1"}
	k.RetainUntil = k.RetainUntil.Add(7 * 24 * time.Hour)
	if err := s.Update(context.Background(), k); err != nil {
		t.Fatalf("Update: %v", err)
	}
	want := k
	want.Revision = 2
	expectInstanceKey(t, s, "after Update", want)

	stale := k // still Revision 1
	stale.Status.Idx = 10
	if err := s.Update(context.Background(), stale); !errors.Is(err, walletprovider.ErrConflict) {
		t.Fatalf("Update(stale revision) = %v, want ErrConflict", err)
	}
	expectInstanceKey(t, s, "after a stale Update", want)
}

func instanceKeyUpdateUnknown(t *testing.T, s walletprovider.InstanceKeyStore) {
	k := sampleInstanceKey("nope", "a")
	k.Revision = 1
	if err := s.Update(context.Background(), k); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Update(unknown) = %v, want ErrNotFound", err)
	}
}

func instanceKeyUpdateKeepsInstance(t *testing.T, s walletprovider.InstanceKeyStore) {
	mustCreateInstanceKey(t, s, sampleInstanceKey("tp-1", "a"))
	want := mustGetInstanceKey(t, s, "tp-1")
	moved := want
	moved.InstanceID = "b"
	if err := s.Update(context.Background(), moved); err == nil || errors.Is(err, walletprovider.ErrConflict) || errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Update moving the key to another instance = %v, want it refused", err)
	}
	expectInstanceKey(t, s, "after a refused Update", want)
	if page, err := s.List(context.Background(), "b", "", 10); err != nil || len(page) != 0 {
		t.Fatalf("List(the other instance) = %v, %v; want none", page, err)
	}
}

func instanceKeyConcurrentUpdates(t *testing.T, s walletprovider.InstanceKeyStore) {
	k := sampleInstanceKey("tp-1", "a")
	k.Status.Idx = 0
	mustCreateInstanceKey(t, s, k)
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wg.Go(func() {
			for {
				cur, err := s.Get(context.Background(), "tp-1")
				if err != nil {
					errs <- err
					return
				}
				cur.Status.Idx++
				if err := s.Update(context.Background(), cur); !errors.Is(err, walletprovider.ErrConflict) {
					if err != nil {
						errs <- err
					}
					return
				}
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Update: %v", err)
	}
	got := mustGetInstanceKey(t, s, "tp-1")
	if got.Status.Idx != workers || got.Revision != workers+1 {
		t.Fatalf("after %d concurrent increments: Status.Idx %d, Revision %d; want %d, %d", workers, got.Status.Idx, got.Revision, workers, workers+1)
	}
}

func instanceKeyListPages(t *testing.T, s walletprovider.InstanceKeyStore) {
	const n = 7
	for i := n - 1; i >= 0; i-- {
		mustCreateInstanceKey(t, s, sampleInstanceKey(fmt.Sprintf("tp-%02d", i), "a"))
		mustCreateInstanceKey(t, s, sampleInstanceKey(fmt.Sprintf("tp-b-%02d", i), "b"))
	}
	var seen []string
	after := ""
	for range n + 1 {
		page, err := s.List(context.Background(), "a", after, 3)
		if err != nil {
			t.Fatalf("List: %v", err)
		}
		if len(page) > 3 {
			t.Fatalf("List(limit 3) returned %d", len(page))
		}
		for _, k := range page {
			if k.InstanceID != "a" {
				t.Fatalf("List(instance a) returned instance %q's key %q", k.InstanceID, k.Thumbprint)
			}
			seen = append(seen, k.Thumbprint)
		}
		if len(page) < 3 {
			break
		}
		after = page[len(page)-1].Thumbprint
	}
	want := []string{"tp-00", "tp-01", "tp-02", "tp-03", "tp-04", "tp-05", "tp-06"}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("paging through List saw %v, want %v", seen, want)
	}
	if page, err := s.List(context.Background(), "c", "", 3); err != nil || len(page) != 0 {
		t.Fatalf("List(an instance with no keys) = %v, %v; want none", page, err)
	}
}

// instanceKeyListUnretained checks a store that's an
// UnretainedInstanceKeyLister, and passes one that isn't.
func instanceKeyListUnretained(t *testing.T, s walletprovider.InstanceKeyStore) {
	lister, ok := s.(walletprovider.UnretainedInstanceKeyLister)
	if !ok {
		t.Skip("not an UnretainedInstanceKeyLister")
	}
	ctx := context.Background()
	for i := 6; i >= 0; i-- {
		k := sampleInstanceKey(fmt.Sprintf("tp-%02d", i), []string{"a", "b"}[i%2])
		if i%3 != 0 {
			k.RetainUntil = time.Time{}
		}
		mustCreateInstanceKey(t, s, k)
	}
	list := func() []string {
		t.Helper()
		var seen []string
		for after := ""; ; {
			page, err := lister.ListUnretained(ctx, after, 2)
			if err != nil {
				t.Fatalf("ListUnretained: %v", err)
			}
			if len(page) > 2 {
				t.Fatalf("ListUnretained(limit 2) returned %d", len(page))
			}
			for _, k := range page {
				if !k.RetainUntil.IsZero() {
					t.Fatalf("ListUnretained returned %q, with RetainUntil %v", k.Thumbprint, k.RetainUntil)
				}
				seen = append(seen, k.Thumbprint)
			}
			if len(page) < 2 {
				return seen
			}
			after = page[len(page)-1].Thumbprint
		}
	}
	if got, want := list(), []string{"tp-01", "tp-02", "tp-04", "tp-05"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("paging through ListUnretained saw %v, want %v", got, want)
	}
	k := mustGetInstanceKey(t, s, "tp-02")
	k.RetainUntil = k.CreatedAt.Add(time.Hour)
	if err := s.Update(ctx, k); err != nil {
		t.Fatal(err)
	}
	if got, want := list(), []string{"tp-01", "tp-04", "tp-05"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("after giving tp-02 a RetainUntil, ListUnretained saw %v, want %v", got, want)
	}
}

func instanceKeyCopies(t *testing.T, s walletprovider.InstanceKeyStore) {
	k := sampleInstanceKey("tp-1", "a")
	mustCreateInstanceKey(t, s, k)
	k.Key[0] = 'X' // the caller's copy, after Create
	got, err := s.Get(context.Background(), "tp-1")
	if err != nil {
		t.Fatal(err)
	}
	got.Key[1] = 'X' // a returned copy
	listed, err := s.List(context.Background(), "a", "", 1)
	if err != nil || len(listed) != 1 {
		t.Fatalf("List = %v, %v", listed, err)
	}
	listed[0].Key[2] = 'X'
	updated := mustGetInstanceKey(t, s, "tp-1")
	if err := s.Update(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	updated.Key[3] = 'X' // the caller's copy, after Update
	again, err := s.Get(context.Background(), "tp-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.Key[0] == 'X' || again.Key[1] == 'X' || again.Key[2] == 'X' || again.Key[3] == 'X' {
		t.Fatalf("the stored record shares memory with the caller's: %s", again.Key)
	}
}

// TestChallengeStoreContract checks that the stores newStore returns
// behave as walletprovider.ChallengeStore requires. newStore returns a
// new, empty store each time it's called.
func TestChallengeStoreContract(t *testing.T, newStore func(t *testing.T) walletprovider.ChallengeStore) {
	t.Helper()
	cases := []struct {
		name string
		run  func(*testing.T, walletprovider.ChallengeStore)
	}{
		{"ConsumeUnknownIsNotFound", challengeConsumeUnknown},
		{"ConsumeOnce", challengeConsumeOnce},
		{"CreateDuplicateIsExists", challengeCreateDuplicate},
		{"ConsumeReturnsExpired", challengeConsumeExpired},
		{"ConcurrentConsumesSucceedOnce", challengeConcurrentConsumes},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { tc.run(t, newStore(t)) })
	}
}

func sampleChallenge(value string) walletprovider.ChallengeRecord {
	at := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	return walletprovider.ChallengeRecord{Value: value, Purpose: walletprovider.PurposeHolder, CreatedAt: at, ExpiresAt: at.Add(5 * time.Minute)}
}

func mustCreateChallenge(t *testing.T, s walletprovider.ChallengeStore, rec walletprovider.ChallengeRecord) {
	t.Helper()
	if err := s.Create(context.Background(), rec); err != nil {
		t.Fatalf("Create(%q): %v", rec.Value, err)
	}
}

func expectChallenge(t *testing.T, got, want walletprovider.ChallengeRecord) {
	t.Helper()
	if got.Value != want.Value || got.Purpose != want.Purpose || !got.CreatedAt.Equal(want.CreatedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("Consume = %+v, want %+v", got, want)
	}
}

func challengeConsumeUnknown(t *testing.T, s walletprovider.ChallengeStore) {
	if _, err := s.Consume(context.Background(), "nope"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("Consume(unknown) = %v, want ErrNotFound", err)
	}
}

func challengeConsumeOnce(t *testing.T, s walletprovider.ChallengeStore) {
	rec := sampleChallenge("c1")
	mustCreateChallenge(t, s, rec)
	mustCreateChallenge(t, s, sampleChallenge("c2"))
	got, err := s.Consume(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	expectChallenge(t, got, rec)
	if _, err := s.Consume(context.Background(), "c1"); !errors.Is(err, walletprovider.ErrNotFound) {
		t.Fatalf("second Consume = %v, want ErrNotFound", err)
	}
	if _, err := s.Consume(context.Background(), "c2"); err != nil {
		t.Fatalf("Consume of the other challenge: %v", err)
	}
}

func challengeCreateDuplicate(t *testing.T, s walletprovider.ChallengeStore) {
	rec := sampleChallenge("c1")
	mustCreateChallenge(t, s, rec)
	other := rec
	other.Purpose = walletprovider.PurposeInstance
	if err := s.Create(context.Background(), other); !errors.Is(err, walletprovider.ErrExists) {
		t.Fatalf("Create(duplicate) = %v, want ErrExists", err)
	}
	got, err := s.Consume(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	expectChallenge(t, got, rec)
}

func challengeConsumeExpired(t *testing.T, s walletprovider.ChallengeStore) {
	rec := sampleChallenge("c1")
	rec.CreatedAt, rec.ExpiresAt = rec.CreatedAt.Add(-time.Hour), rec.CreatedAt.Add(-time.Minute)
	mustCreateChallenge(t, s, rec)
	got, err := s.Consume(context.Background(), "c1")
	if err != nil {
		t.Fatalf("Consume(expired): %v; the provider, not the store, refuses it", err)
	}
	expectChallenge(t, got, rec)
}

func challengeConcurrentConsumes(t *testing.T, s walletprovider.ChallengeStore) {
	mustCreateChallenge(t, s, sampleChallenge("c1"))
	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := 0
	var unexpected []error
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Consume(context.Background(), "c1")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
			case !errors.Is(err, walletprovider.ErrNotFound):
				unexpected = append(unexpected, err)
			}
		}()
	}
	wg.Wait()
	if len(unexpected) > 0 {
		t.Fatalf("concurrent Consume: %v", unexpected)
	}
	if succeeded != 1 {
		t.Fatalf("%d concurrent Consumes of one challenge succeeded, want 1", succeeded)
	}
}
