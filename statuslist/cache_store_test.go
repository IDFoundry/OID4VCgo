package statuslist

import (
	"crypto/sha256"
	"encoding/hex"
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

	// A record loaded since is used more recently than one saved before.
	big, err := NewDirCacheStore(t.TempDir(), 12)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"p", "q"} {
		if err := big.Save(name, []byte("123456")); err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"p", "q"} {
		saved := time.Now().Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(filepath.Join(big.dir, name+recordSuffix), saved, saved); err != nil {
			t.Fatal(err)
		}
	}
	if got, _ := big.Load("p"); string(got) != "123456" {
		t.Fatalf("p = %q", got)
	}
	if err := big.Save("r", []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if got, _ := big.Load("p"); got == nil {
		t.Error("p, loaded last, was evicted")
	}
	if got, _ := big.Load("q"); got != nil {
		t.Error("q, used least recently, was kept")
	}
	if err := big.Touch("none"); err != nil {
		t.Errorf("Touch of nothing = %v", err)
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

// A list a 304 confirmed after others were saved is used more recently
// than they are: it survives the eviction a new list's save makes.
func TestCache_DirStoreEvictsLeastRecentlyUsed(t *testing.T) {
	s := newCacheServer(t)
	s.set(func(s *cacheServer) { s.etag = true })
	dir := t.TempDir()
	store, err := NewDirCacheStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := s.checker(NewCache(CacheOptions{MaxAge: time.Minute, Now: s.clock.Now, Store: store}))
	file := func(path string) string {
		return filepath.Join(dir, recordName(path, s)+recordSuffix)
	}
	s.check(t, c, "/a", 0, false)
	info, err := os.Stat(file("/a"))
	if err != nil {
		t.Fatal(err)
	}
	// Room for two records, not three.
	store.maxBytes = info.Size()*2 + info.Size()/2
	s.check(t, c, "/b", 0, false)
	for i, path := range []string{"/a", "/b"} {
		saved := time.Now().Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(file(path), saved, saved); err != nil {
			t.Fatal(err)
		}
	}
	// /a, saved first, is revalidated: a 304.
	s.clock.Add(time.Minute)
	s.check(t, c, "/a", 0, false)
	if got := s.notModifieds.Load(); got != 1 {
		t.Fatalf("%d 304s, want /a revalidated", got)
	}
	s.check(t, c, "/c", 0, false)
	if _, err := os.Stat(file("/a")); err != nil {
		t.Errorf("/a, revalidated last, was evicted: %v", err)
	}
	if _, err := os.Stat(file("/b")); err == nil {
		t.Error("/b, used least recently, was kept")
	}
	if _, err := os.Stat(file("/c")); err != nil {
		t.Errorf("/c, just saved, wasn't kept: %v", err)
	}
}

// recordName is the name a Cache keeps path's JWT list under on s.
func recordName(path string, s *cacheServer) string {
	sum := sha256.Sum256([]byte(s.uri(path) + "\x00" + TokenMediaType))
	return hex.EncodeToString(sum[:])
}
