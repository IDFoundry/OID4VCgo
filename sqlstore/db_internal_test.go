package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// A SQLite write waiting for another of the DB's writes to finish gives
// up as soon as its context is done.
func TestSQLiteWriteWaitHonoursContext(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "store.db")+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	d, err := New(db, SQLite, Options{})
	if err != nil {
		t.Fatal(err)
	}

	holding, release := make(chan struct{}), make(chan struct{})
	held := make(chan error, 1)
	go func() {
		held <- d.write(context.Background(), func(querier) error {
			close(holding)
			<-release
			return nil
		})
	}()
	<-holding

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = d.write(ctx, func(querier) error {
		t.Error("a write ran while another held the lock")
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiting write = %v, want context.DeadlineExceeded", err)
	}
	if waited := time.Since(start); waited > 5*time.Second {
		t.Errorf("waiting write returned after %v", waited)
	}

	close(release)
	if err := <-held; err != nil {
		t.Errorf("holding write: %v", err)
	}
	// The slot is free again.
	if err := d.write(context.Background(), func(querier) error { return nil }); err != nil {
		t.Errorf("write after release: %v", err)
	}
}
