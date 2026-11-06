package statuslist

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// DefaultDirCacheStoreMaxBytes is NewDirCacheStore's default bound on
// the records it keeps: 64 MiB, as a Cache's default MaxBytes.
const DefaultDirCacheStoreMaxBytes = 64 << 20

// recordSuffix ends the name of each file a DirCacheStore keeps.
const recordSuffix = ".statuslist"

// DirCacheStore is a CacheStore keeping each record as a file in a
// directory: an app's cache directory, say, which the platform may
// clear, costing a download. It keeps at most maxBytes of records,
// removing the least recently used first: a record's modification time
// is when it was last saved, loaded or touched (a 304 confirming it).
//
// Records are written to a temporary file and renamed into place, so
// a process that stops mid-write leaves the old record or none. The
// directory should be the app's own: what's in it is only ever
// revalidated with a list's server before use (CacheStore), but a
// process able to write it can make each launch download its lists.
type DirCacheStore struct {
	dir      string
	maxBytes int64
	mu       sync.Mutex
}

// NewDirCacheStore returns a DirCacheStore keeping records in dir,
// which it creates if needed, bounded to maxBytes in all; zero or
// negative means DefaultDirCacheStoreMaxBytes.
func NewDirCacheStore(dir string, maxBytes int64) (*DirCacheStore, error) {
	if dir == "" {
		return nil, errors.New("statuslist: DirCacheStore needs a directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("statuslist: cache directory: %w", err)
	}
	if maxBytes <= 0 {
		maxBytes = DefaultDirCacheStoreMaxBytes
	}
	return &DirCacheStore{dir: dir, maxBytes: maxBytes}, nil
}

func (s *DirCacheStore) path(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\.`) {
		return "", fmt.Errorf("statuslist: cache record name %q", name)
	}
	return filepath.Join(s.dir, name+recordSuffix), nil
}

// Load implements CacheStore.
func (s *DirCacheStore) Load(name string) ([]byte, error) {
	p, err := s.path(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p) // #nosec G304 -- p is the store's directory joined with a name path checked has no separator or dot
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err == nil {
		// Used: evicted after the records used less recently.
		_ = s.Touch(name)
	}
	return data, err
}

// Touch marks the record kept under name used now, so that it's
// evicted after records used less recently; nil when none is kept.
func (s *DirCacheStore) Touch(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := os.Chtimes(p, now, now); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// Save implements CacheStore. A record larger than the store's bound
// isn't kept.
func (s *DirCacheStore) Save(name string, record []byte) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if int64(len(record)) > s.maxBytes {
		return s.Remove(name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tmp, err := os.CreateTemp(s.dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // gone once renamed
	if _, err := tmp.Write(record); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	return s.prune(p)
}

// prune removes the least recently used records, but never keep, until
// the store is within its bound; s.mu is held.
func (s *DirCacheStore) prune(keep string) error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	type file struct {
		path string
		size int64
		mod  time.Time
	}
	var files []file
	var total int64
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), recordSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		files = append(files, file{filepath.Join(s.dir, e.Name()), info.Size(), info.ModTime()})
		total += info.Size()
	}
	slices.SortFunc(files, func(a, b file) int { return a.mod.Compare(b.mod) })
	for _, f := range files {
		if total <= s.maxBytes {
			break
		}
		if f.path == keep {
			continue
		}
		if err := os.Remove(f.path); err == nil || errors.Is(err, fs.ErrNotExist) {
			total -= f.size
		}
	}
	return nil
}

// Remove implements CacheStore.
func (s *DirCacheStore) Remove(name string) error {
	p, err := s.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
