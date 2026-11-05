package mobile

import (
	"fmt"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// status_max_bytes and identifier_list_max_bytes bound the lists a
// Wallet's and a reader's CheckStatus read; either outside its
// package's limits is invalid_input.
func TestStatusMaxBytes(t *testing.T) {
	ca, _ := testcert.CA(t, "IACA")
	roots := `"issuer_roots": ` + jsonString(pemOf("CERTIFICATE", ca.Raw))
	r, err := NewProximityReader(`{"development": true, `+roots+`, "status_max_bytes": 2097152, "identifier_list_max_bytes": 8388608}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.statusMaxBytes != 2<<20 || r.identifierListMaxBytes != 8<<20 {
		t.Errorf("reader limits = %d, %d", r.statusMaxBytes, r.identifierListMaxBytes)
	}
	if _, err := NewWallet(`{"development": true, "status_max_bytes": 2097152, "identifier_list_max_bytes": 8388608}`,
		newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); err != nil {
		t.Errorf("NewWallet: %v", err)
	}
	for key, limit := range map[string]int{"status_max_bytes": statuslist.MaxTokenBytesLimit, "identifier_list_max_bytes": identifierlist.MaxTokenBytesLimit} {
		for _, n := range []int{-1, limit + 1} {
			cfg := fmt.Sprintf(`{"development": true, %q: %d}`, key, n)
			if _, err := NewProximityReader(fmt.Sprintf(`{"development": true, %s, %q: %d}`, roots, key, n), nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "not between 0 and") {
				t.Errorf("reader %s: %v", cfg, err)
			}
			if _, err := NewWallet(cfg, newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "not between 0 and") {
				t.Errorf("wallet %s: %v", cfg, err)
			}
		}
	}
}
