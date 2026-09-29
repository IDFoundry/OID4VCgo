package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResetState(t *testing.T) {
	write := func(t *testing.T, dir, name string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(dir string) bool { _, err := os.Stat(dir); return os.IsNotExist(err) }

	t.Run("refuses an unrelated directory", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "important.txt")
		if err := resetState(dir); err == nil || gone(dir) {
			t.Fatalf("resetState deleted a directory the demo didn't make (err %v)", err)
		}
	})
	t.Run("deletes a marked state directory", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		write(t, dir, stateMarker)
		write(t, dir, "wallet-store/cred.json")
		if err := resetState(dir); err != nil || !gone(dir) {
			t.Fatalf("resetState = %v, deleted %v", err, gone(dir))
		}
	})
	t.Run("deletes a state directory made before the marker", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "state")
		write(t, dir, "tls-cert.pem")
		write(t, dir, "issuer/issuer-identity.pem")
		if err := resetState(dir); err != nil || !gone(dir) {
			t.Fatalf("resetState = %v, deleted %v", err, gone(dir))
		}
	})
	t.Run("accepts a missing or empty directory", func(t *testing.T) {
		if err := resetState(filepath.Join(t.TempDir(), "never-created")); err != nil {
			t.Error(err)
		}
		if err := resetState(t.TempDir()); err != nil {
			t.Error(err)
		}
	})
}
