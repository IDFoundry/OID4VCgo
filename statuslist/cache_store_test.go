package statuslist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A Cache over a DirCacheStore an earlier Cache filled — an app's
// earlier launch — revalidates each list it kept instead of downloading
// it, in both forms; a damaged record is downloaded again.
func TestCache_DirStoreAcrossProcesses(t *testing.T) {
	for _, cwt := range []bool{false, true} {
		s := newCacheServer(t)
		s.set(func(s *cacheServer) { s.etag = true })
		dir := t.TempDir()
		launch := func() Checker {
			store, err := NewDirCacheStore(dir, 0)
			if err != nil {
				t.Fatal(err)
			}
			return s.checker(NewCache(CacheOptions{Now: s.clock.Now, Store: store}))
		}
		s.check(t, launch(), "/l", 0, cwt)
		if got := s.check(t, launch(), "/l", 1, cwt); got != StatusInvalid {
			t.Errorf("cwt=%v: index 1 is %v from a kept list", cwt, got)
		}
		if got := s.notModifieds.Load(); got != 1 {
			t.Errorf("cwt=%v: %d 304s, want the kept list revalidated", cwt, got)
		}
		files, _ := filepath.Glob(filepath.Join(dir, "*"+recordSuffix))
		if len(files) != 1 {
			t.Fatalf("cwt=%v: %d records, want 1", cwt, len(files))
		}
		if err := os.WriteFile(files[0], []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.check(t, launch(), "/l", 0, cwt)
		if got := s.notModifieds.Load(); got != 1 {
			t.Errorf("cwt=%v: %d 304s, want a damaged record downloaded again", cwt, got)
		}
		s.wantFetches(t, 3, "three launches")
	}
}

func TestDirCacheStore(t *testing.T) {
	dir := t.TempDir()
	s, err := NewDirCacheStore(dir, 10)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Load("a"); got != nil || err != nil {
		t.Fatalf("Load of nothing = %q, %v", got, err)
	}
	for _, name := range []string{"", "../a", "a.b", `a\b`} {
		if err := s.Save(name, []byte("x")); err == nil {
			t.Errorf("Save(%q) passed", name)
		}
	}
	if err := s.Save("a", []byte("123456")); err != nil {
		t.Fatal(err)
	}
	// Older, so that it's pruned first.
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "a"+recordSuffix), old, old); err != nil {
		t.Fatal(err)
	}
	if err := s.Save("b", []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load("a"); got != nil {
		t.Errorf("a = %q, want it pruned to stay within 10 bytes", got)
	}
	if got, _ := s.Load("b"); string(got) != "123456" {
		t.Errorf("b = %q", got)
	}
	if err := s.Save("c", make([]byte, 11)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Load("c"); got != nil {
		t.Error("a record over the bound was kept")
	}
	if err := s.Remove("b"); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("b"); err != nil {
		t.Errorf("Remove of nothing = %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Errorf("%d files left, want none", len(entries))
	}
}
