package issuerapp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

// testListURI is the status list the tests' lists are at.
const testListURI = "https://issuer.example" + StatusListPath

// indexStores open, for a test, each durable store the issuer keeps
// its status list's indices in: a file in its state directory, and a
// database. Each call opens the store afresh, as a restart does.
var indexStores = map[string]func(t *testing.T, dir string) statuslist.IndexStore{
	"file": func(t *testing.T, dir string) statuslist.IndexStore {
		t.Helper()
		s, err := openFileIndexStore(filepath.Join(dir, statusIndicesFile))
		if err != nil {
			t.Fatal(err)
		}
		return s
	},
	"database": func(t *testing.T, dir string) statuslist.IndexStore {
		t.Helper()
		db, sealer, err := OpenDatabase(filepath.Join(dir, "stores.db"), filepath.Join(dir, "stores.key"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		d, err := sqlstore.New(db, sqlstore.SQLite, sqlstore.Options{Sealer: sealer})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Migrate(context.Background()); err != nil {
			t.Fatal(err)
		}
		return d.StatusIndices()
	},
}

// memoryStatusList is a status list in memory, as an issuer without
// StateDir or Database keeps it.
func memoryStatusList(t *testing.T) *statusList {
	t.Helper()
	s, err := loadStatusList(context.Background(), &statuslist.MemoryIndexStore{}, testListURI, "")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// statusesOf is what s's publishers serve.
func statusesOf(t *testing.T, s *statusList) []uint8 {
	t.Helper()
	statuses, err := s.statuses(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return statuses
}

// drawing is an Allocator.Rand drawing idxs in turn.
func drawing(idxs ...uint64) *bytes.Reader {
	var b []byte
	for _, idx := range idxs {
		b = binary.BigEndian.AppendUint64(b, idx)
	}
	return bytes.NewReader(b)
}

// TestStatusList_PersistsAcrossRestart: allocations and revocations
// survive a reload, in the state directory's file and in the database;
// a released index's entry doesn't, but the index stays reserved.
func TestStatusList_PersistsAcrossRestart(t *testing.T) {
	ctx := context.Background()
	for name, open := range indexStores {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s, err := loadStatusList(ctx, open(t, dir), testListURI, dir)
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			now := time.Now().Truncate(time.Second)
			kept, err := s.allocate(ctx, "dc+sd-jwt", true, "1", now)
			if err != nil {
				t.Fatal(err)
			}
			revoked, err := s.allocate(ctx, "mso_mdoc", false, "1", now)
			if err != nil {
				t.Fatal(err)
			}
			released, err := s.allocate(ctx, "mso_mdoc", false, "1", now)
			if err != nil {
				t.Fatal(err)
			}
			s.release(released)
			if found, err := s.revoke(ctx, revoked); !found || err != nil {
				t.Fatalf("revoke = %v, %v", found, err)
			}

			store := open(t, dir)
			reloaded, err := loadStatusList(ctx, store, testListURI, dir)
			if err != nil {
				t.Fatalf("reload: %v", err)
			}
			entries := reloaded.snapshot()
			if len(entries) != 2 {
				t.Fatalf("reloaded %d entries, want 2", len(entries))
			}
			bits := statusesOf(t, reloaded)
			if bits[kept] != 0 || bits[revoked] != 1 || !reloaded.entries[revoked].Revoked || reloaded.entries[kept].Revoked {
				t.Errorf("reloaded status bits: kept=%d revoked=%d, want 0 and 1", bits[kept], bits[revoked])
			}
			if _, ok := reloaded.entries[released]; ok {
				t.Error("a released index's entry came back after reload")
			}
			if n, err := store.Reserved(ctx, testListURI); err != nil || n != 3 {
				t.Errorf("Reserved = %d, %v after reload, want all 3 allocated indices", n, err)
			}
			if _, err := store.Status(ctx, testListURI, uint64(released)); err != nil { // #nosec G115 -- a status list index
				t.Errorf("a released index isn't reserved after reload: %v", err)
			}
			if !reloaded.entries[kept].Unchecked || reloaded.entries[revoked].Unchecked {
				t.Error("whether a credential was issued unchecked didn't survive reload")
			}
		})
	}
}

// TestStatusList_NeverReusesIndices: allocation goes through the
// Allocator: every index is new, and a released one, whose credential
// wasn't issued, isn't handed out again.
func TestStatusList_NeverReusesIndices(t *testing.T) {
	ctx := context.Background()
	s := memoryStatusList(t)
	s.allocator.Rand = drawing(7, 7, 7, 12)
	first, err := s.allocate(ctx, "mso_mdoc", false, "1", time.Now())
	if err != nil || first != 7 {
		t.Fatalf("allocate = %d, %v, want 7", first, err)
	}
	s.release(first)
	second, err := s.allocate(ctx, "mso_mdoc", false, "1", time.Now())
	if err != nil || second != 12 {
		t.Fatalf("allocate after releasing 7 = %d, %v, want 12: a released index was handed out again", second, err)
	}

	s.allocator.Rand = nil
	seen := map[int]bool{first: true, second: true}
	for range 500 {
		idx, err := s.allocate(ctx, "dc+sd-jwt", false, "1", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[idx] {
			t.Fatalf("index %d handed out twice", idx)
		}
		seen[idx] = true
		if len(seen)%2 == 0 {
			s.release(idx)
		}
	}
}

// TestStatusList_Full: once the Allocator's fill limit is reached,
// allocating fails with the error the Credential Endpoint has always
// answered with.
func TestStatusList_Full(t *testing.T) {
	ctx := context.Background()
	s := memoryStatusList(t)
	for idx := range uint64(statusListSize / 2) {
		if err := s.allocator.Store.Reserve(ctx, testListURI, idx); err != nil {
			t.Fatal(err)
		}
	}
	_, err := s.allocate(ctx, "mso_mdoc", false, "1", time.Now())
	if !errors.Is(err, errStatusListFull) || !errors.Is(err, statuslist.ErrListsFull) {
		t.Fatalf("allocate on a full list = %v, want errStatusListFull", err)
	}
	if len(s.snapshot()) != 0 {
		t.Error("a failed allocation left an entry")
	}
}

// TestStatusList_MigratesSavedList: a status-list.json from before the
// store held the reservations has its indices reserved and its revoked
// entries INVALID on load, so no index is handed out again; loading
// again changes nothing; and a revocation the store holds but the entry
// missed is taken from the store.
func TestStatusList_MigratesSavedList(t *testing.T) {
	ctx := context.Background()
	issued := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	saved, err := json.Marshal([]IssuedStatus{
		{Idx: 5, Handle: "valid", Format: "dc+sd-jwt", IssuedAt: issued, Signer: "1"},
		{Idx: 9, Handle: "revoked", Format: "mso_mdoc", IssuedAt: issued, Revoked: true, Signer: "1"},
		{Idx: 300, Format: "mso_mdoc", IssuedAt: issued}, // no handle, no signer: older still
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, open := range indexStores {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, statusListFile), saved, 0o600); err != nil {
				t.Fatal(err)
			}
			for range 2 { // the second load finds the reservations made
				store := open(t, dir)
				s, err := loadStatusList(ctx, store, testListURI, dir)
				if err != nil {
					t.Fatalf("load: %v", err)
				}
				if n, err := store.Reserved(ctx, testListURI); err != nil || n != 3 {
					t.Fatalf("Reserved = %d, %v, want the 3 saved indices", n, err)
				}
				bits := statusesOf(t, s)
				if bits[5] != 0 || bits[9] != 1 || bits[300] != 0 {
					t.Errorf("statuses 5, 9, 300 = %d, %d, %d, want 0, 1, 0", bits[5], bits[9], bits[300])
				}
				if s.entries[300].Handle == "" {
					t.Error("an entry saved without a handle wasn't given one")
				}
			}

			store := open(t, dir)
			s, err := loadStatusList(ctx, store, testListURI, dir)
			if err != nil {
				t.Fatal(err)
			}
			s.allocator.Rand = drawing(5, 9, 300, 11)
			if idx, err := s.allocate(ctx, "mso_mdoc", false, "1", time.Now()); err != nil || idx != 11 {
				t.Fatalf("allocate = %d, %v, want 11, the first index not saved", idx, err)
			}

			// The store revoked 5, but the entry wasn't saved.
			if err := store.SetStatus(ctx, testListURI, 5, statuslist.StatusInvalid); err != nil {
				t.Fatal(err)
			}
			s, err = loadStatusList(ctx, open(t, dir), testListURI, dir)
			if err != nil {
				t.Fatal(err)
			}
			if !s.entries[5].Revoked {
				t.Error("an entry the store has revoked loaded as valid")
			}
		})
	}
}

func TestStatusList_RejectsDamagedFile(t *testing.T) {
	ctx := context.Background()
	for name, content := range map[string]string{
		"not JSON":     "{",
		"out of range": `[{"Idx":70000,"Format":"mso_mdoc"}]`,
	} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, statusListFile), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadStatusList(ctx, &statuslist.MemoryIndexStore{}, testListURI, dir); err == nil {
			t.Errorf("%s: a damaged status list was accepted", name)
		}
	}
	for name, content := range map[string]string{
		"not JSON":     "{",
		"out of range": `{"` + testListURI + `":{"70000":0}}`,
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, statusIndicesFile)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		store, err := openFileIndexStore(path)
		if err == nil {
			_, err = loadStatusList(ctx, store, testListURI, dir)
		}
		if err == nil {
			t.Errorf("%s: damaged status list indices were accepted", name)
		}
	}
}

// TestStatusList_InMemoryWithoutStateDir: an issuer without StateDir
// writes nothing.
func TestStatusList_InMemoryWithoutStateDir(t *testing.T) {
	s := memoryStatusList(t)
	if _, err := s.allocate(context.Background(), "mso_mdoc", false, "1", time.Now()); err != nil {
		t.Fatal(err)
	}
	if s.path != "" {
		t.Error("an in-memory status list has a file")
	}
}

// TestStatusList_RefusesHTTPURI: the Allocator serves only an https
// list, and the issuer says so when it starts, not at its first
// credential.
func TestStatusList_RefusesHTTPURI(t *testing.T) {
	if _, err := loadStatusList(context.Background(), &statuslist.MemoryIndexStore{}, "http://127.0.0.1"+StatusListPath, ""); err == nil {
		t.Error("a status list at an http URI was accepted")
	}
}

// TestStatusPage_HidesIndices: the public revocation page names entries
// by handle, never by status list index, and a handle revokes its entry.
func TestStatusPage_HidesIndices(t *testing.T) {
	ctx := context.Background()
	s := memoryStatusList(t)
	idx, err := s.allocate(ctx, "mso_mdoc", false, "1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entries := s.snapshot()
	var page strings.Builder
	if err := statusTemplate.Execute(&page, statusPage{URI: testListURI, Entries: entries}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(page.String(), ">"+strconv.Itoa(idx)+"<") || strings.Contains(page.String(), `name="idx"`) {
		t.Error("the revocation page shows a status list index")
	}
	if !strings.Contains(page.String(), `value="`+entries[0].Handle+`"`) {
		t.Error("the revocation page doesn't name the entry by its handle")
	}
	for _, handle := range []string{"", "unknown"} {
		if found, err := s.revokeHandle(ctx, handle); found || err != nil {
			t.Errorf("revokeHandle(%q) = %v, %v: revoked something", handle, found, err)
		}
	}
	if found, err := s.revokeHandle(ctx, entries[0].Handle); !found || err != nil {
		t.Fatalf("revoking by handle = %v, %v", found, err)
	}
	if bits := statusesOf(t, s); bits[idx] != 1 {
		t.Error("the handle didn't revoke its entry")
	}
}

// TestStatusPage_ShowsIssuanceDayOnly: the revocation page dates an
// entry by its UTC day, which every credential issued that day shares,
// not by a time a verifier could match a presented credential to.
func TestStatusPage_ShowsIssuanceDayOnly(t *testing.T) {
	s := memoryStatusList(t)
	issued := time.Date(2026, 9, 26, 13, 47, 5, 0, time.UTC)
	if _, err := s.allocate(context.Background(), "mso_mdoc", false, "1", issued); err != nil {
		t.Fatal(err)
	}
	var page strings.Builder
	if err := statusTemplate.Execute(&page, statusPage{URI: testListURI, Entries: s.snapshot()}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(page.String(), ">2026-09-26<") {
		t.Error("the revocation page doesn't date the entry by its day")
	}
	if strings.Contains(page.String(), "13:47") {
		t.Error("the revocation page shows the time of issuance")
	}
}
