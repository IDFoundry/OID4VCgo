package walletapp

import (
	"reflect"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
)

// A claim path's index and wildcard elements are rendered by kind, not
// as empty keys.
func TestPathStrings_RendersEachKind(t *testing.T) {
	got := pathStrings([]dcql.Path{{dcql.PathKey("nationalities"), dcql.PathIndex(1)}, {dcql.PathKey("address"), dcql.Wildcard, dcql.PathKey("country")}})
	want := [][]string{{"nationalities", "1"}, {"address", "*", "country"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pathStrings = %q, want %q", got, want)
	}
}
