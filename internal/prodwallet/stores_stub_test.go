//go:build !conformance_production

package prodwallet_test

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
)

func TestOpenNeedsTheTag(t *testing.T) {
	if _, err := prodwallet.Open(t.TempDir()); !errors.Is(err, prodwallet.ErrNotBuilt) || prodwallet.Built {
		t.Fatalf("Open: %v, Built %v; want ErrNotBuilt", err, prodwallet.Built)
	}
	var s *prodwallet.Stores
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
