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
		Credential: []byte{1, 2, 3}, Counter: 7,
		State: walletprovider.StateSuspended, Reason: "lost device",
		Status:    statuslist.StatusListRef{Idx: 1234, URI: "https://provider.example/status"},
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
