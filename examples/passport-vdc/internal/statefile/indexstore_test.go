package statefile_test

import (
	"context"
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
