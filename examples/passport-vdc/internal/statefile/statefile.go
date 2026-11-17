// Package statefile writes the demo servers' state files.
package statefile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteAtomic replaces path with data, readable only by its owner: a
// reader sees the old file or the new one, never part of either. The
// new file is flushed to disk before it replaces the old one, and the
// directory after, so once WriteAtomic returns, a crash or power loss
// leaves the new file, not an empty or missing one.
func WriteAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := syncDir(dir); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// syncDir flushes dir's entries, a rename into it among them, to disk.
// On Windows, which can't flush a directory this way, it does nothing.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) // #nosec G304 -- the directory of an operator-supplied state file
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}
