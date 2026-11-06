package mobile

import (
	"fmt"
	"os"
	"path/filepath"
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
	if c, _ := statusCacheFor(3600, ""); c != hour.statusCache {
		t.Error("a reader with a max age of an hour doesn't use the process's Cache for it")
	}
	if c, _ := statusCacheFor(0, ""); c != def.statusCache {
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

// status_cache_dir, an absolute path, gives the process's Cache a
// DirCacheStore there, which Caches with different max ages share; a
// relative path is invalid_input.
func TestStatusCacheDir(t *testing.T) {
	ca, _ := testcert.CA(t, "IACA")
	roots := `"issuer_roots": ` + jsonString(pemOf("CERTIFICATE", ca.Raw))
	dir := filepath.Join(t.TempDir(), "status")
	kept, err := NewProximityReader(`{"development": true, `+roots+`, "status_cache_dir": `+jsonString(dir)+`}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	def, err := NewProximityReader(`{"development": true, `+roots+`}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if kept.statusCache == def.statusCache {
		t.Error("a reader keeping lists in a directory shares the in-memory Cache")
	}
	if c, _ := statusCacheFor(0, dir+"/"); c != kept.statusCache {
		t.Error("the same directory, spelled differently, has another Cache")
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("the directory wasn't created: %v", err)
	}
	statusCaches.Lock()
	n := len(statusCaches.stores)
	statusCaches.Unlock()
	if _, err := statusCacheFor(60, dir); err != nil {
		t.Fatal(err)
	}
	statusCaches.Lock()
	if len(statusCaches.stores) != n {
		t.Error("a second max age over one directory made another store")
	}
	statusCaches.Unlock()
	if _, err := NewWallet(`{"development": true, "status_cache_dir": `+jsonString(dir)+`}`, newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWallet(`{"development": true, "status_cache_dir": "status"}`, newGoKeyStore(), memStore{records: map[string][]byte{}}, nil); code(err) != CodeInvalidInput {
		t.Errorf("a relative status_cache_dir: %v", err)
	}
}
