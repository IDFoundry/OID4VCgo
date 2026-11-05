package mobile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// status_cache_max_age_seconds picks the process's Cache a Wallet and
// a reader keep lists in: one per value, shared by those configured
// alike. A value outside 0 to a day is invalid_input.
func TestStatusCacheMaxAge(t *testing.T) {
	ca, _ := testcert.CA(t, "IACA")
	roots := `"issuer_roots": ` + jsonString(pemOf("CERTIFICATE", ca.Raw))
	hour, err := NewProximityReader(`{"development": true, `+roots+`, "status_cache_max_age_seconds": 3600}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	def, err := NewProximityReader(`{"development": true, `+roots+`}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hour.statusCache == def.statusCache {
		t.Error("readers with different max ages share a Cache")
	}
	if c, _ := statusCacheFor(3600); c != hour.statusCache {
		t.Error("a reader with a max age of an hour doesn't use the process's Cache for it")
	}
	if c, _ := statusCacheFor(0); c != def.statusCache {
		t.Error("a reader without a max age doesn't use the process's default Cache")
	}
	if _, err := NewWallet(`{"development": true, "status_cache_max_age_seconds": 3600}`, newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int64{-1, 86401} {
		if _, err := NewProximityReader(fmt.Sprintf(`{"development": true, %s, "status_cache_max_age_seconds": %d}`, roots, n), nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "not between 0 and") {
			t.Errorf("reader %d: %v", n, err)
		}
		if _, err := NewWallet(fmt.Sprintf(`{"development": true, "status_cache_max_age_seconds": %d}`, n), newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "not between 0 and") {
			t.Errorf("wallet %d: %v", n, err)
		}
	}
}
