package statefile_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/statefile"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/statuslist/statuslisttest"
)

func open(t *testing.T, path string) *statefile.IndexStore {
	t.Helper()
	s, err := statefile.OpenIndexStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestIndexStore_Contract(t *testing.T) {
	statuslisttest.TestIndexStoreContract(t, func(t *testing.T) statuslist.IndexStore {
		return open(t, filepath.Join(t.TempDir(), "indices.json"))
	})
}

// TestIndexStore_DeleteIsSaved: a list deleted is gone from the file
// too, and the other lists are kept.
func TestIndexStore_DeleteIsSaved(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "indices.json")
	const a, b = "https://issuer.example/a", "https://issuer.example/b"
	s := open(t, path)
	for _, uri := range []string{a, b} {
		if err := s.Reserve(ctx, uri, 3); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Delete(ctx, a); err != nil {
		t.Fatal(err)
	}
	again := open(t, path)
	for uri, want := range map[string]int{a: 0, b: 1} {
		if n, err := again.Reserved(ctx, uri); err != nil || n != want {
			t.Fatalf("reopened, Reserved(%s) = %d, %v; want %d", uri, n, err, want)
		}
	}
}

// A file of the earlier format, every reserved index with its status,
// is read with its statuses, and its first change rewrites it
// compactly: a bit an index, not a JSON member, so a Wallet Provider's
// week of registrations stays a file of hundreds of KiB, not tens of
// MiB rewritten on each one.
func TestIndexStore_ReadsEarlierFormatAndCompacts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "indices.json")
	const uri, reserved = "https://provider.example/status/1800000000/0", 50_000
	earlier := map[uint64]statuslist.StatusType{}
	for i := range uint64(reserved) {
		earlier[2*i] = statuslist.StatusValid
	}
	earlier[10] = statuslist.StatusInvalid
	earlier[20] = statuslist.StatusSuspended
	data, err := json.Marshal(map[string]map[uint64]statuslist.StatusType{uri: earlier})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := open(t, path)
	if err := s.Reserve(ctx, uri, 1); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if limit := int64(reserved / 2); fi.Size() > limit {
		t.Errorf("rewritten as %d bytes for %d indices, want at most %d (was %d)", fi.Size(), reserved+1, limit, len(data))
	}
	again := open(t, path)
	if n, err := again.Reserved(ctx, uri); err != nil || n != reserved+1 {
		t.Fatalf("reopened, Reserved = %d, %v; want %d", n, err, reserved+1)
	}
	for idx, want := range map[uint64]statuslist.StatusType{
		0: statuslist.StatusValid, 1: statuslist.StatusValid, 10: statuslist.StatusInvalid, 20: statuslist.StatusSuspended,
	} {
		if got, err := again.Status(ctx, uri, idx); err != nil || got != want {
			t.Errorf("reopened, Status(%d) = %v, %v; want %v", idx, got, err, want)
		}
	}
	if _, err := again.Status(ctx, uri, 3); err == nil {
		t.Error("an index never reserved has a status")
	}
	statuses, err := again.Statuses(ctx, uri, 2*reserved)
	if err != nil || statuses[10] != uint8(statuslist.StatusInvalid) || statuses[20] != uint8(statuslist.StatusSuspended) || statuses[0] != 0 {
		t.Errorf("reopened, Statuses: %v", err)
	}
	if _, err := again.Statuses(ctx, uri, 100); err == nil {
		t.Error("Statuses for a size smaller than the reserved indices: no error")
	}
}

// An index past MaxIndex, whose bitmap would be larger than any list
// needs, is refused.
func TestIndexStore_RefusesIndexPastMax(t *testing.T) {
	s := open(t, filepath.Join(t.TempDir(), "indices.json"))
	if err := s.Reserve(context.Background(), "https://issuer.example/a", statefile.MaxIndex+1); err == nil {
		t.Errorf("Reserve(%d): no error", uint64(statefile.MaxIndex+1))
	}
}
