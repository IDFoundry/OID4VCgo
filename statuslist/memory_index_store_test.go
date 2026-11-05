package statuslist_test

import (
	"testing"

	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/statuslist/statuslisttest"
)

func TestMemoryIndexStoreContract(t *testing.T) {
	statuslisttest.TestIndexStoreContract(t, func(*testing.T) statuslist.IndexStore { return &statuslist.MemoryIndexStore{} })
}
