//go:build conformance_production

package proddb

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOpen(t *testing.T) {
	if _, err := Open("", "", 1); err == nil {
		t.Error("Open with neither a path nor a URL: no error")
	}
	if _, err := Open("x.db", "postgres://localhost/x", 1); err == nil {
		t.Error("Open with both a path and a URL: no error")
	}
	path := filepath.Join(t.TempDir(), "p.db")
	db, err := Open(path, "", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Postgres || db.Name != path {
		t.Errorf("Open(%q) = Postgres %v, Name %q", path, db.Postgres, db.Name)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Errorf("the SQLite file doesn't open: %v", err)
	}
	pg, err := Open("", "postgres://user:secret@localhost:1/x", 3)
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	if !pg.Postgres || strings.Contains(pg.Name, "secret") || pg.Stats().MaxOpenConnections != 3 {
		t.Errorf("Open(a URL) = Postgres %v, Name %q, %d connections", pg.Postgres, pg.Name, pg.Stats().MaxOpenConnections)
	}
}

// sweeper is a Sweeper deleting n records, or failing with err.
type sweeper struct {
	n   int64
	err error
}

func (s sweeper) Sweep(context.Context, time.Time) (int64, error) { return s.n, s.err }

func TestSweepRound(t *testing.T) {
	ok := map[string]Sweeper{"one": sweeper{n: 2}, "two": sweeper{n: 3}}
	if got := sweepRound(time.Second, []string{"one", "two"}, ok); got != "sweep: deleted 5 expired records" {
		t.Errorf("sweepRound = %q", got)
	}
	failing := map[string]Sweeper{"one": sweeper{n: 2}, "two": sweeper{err: errors.New("boom")}}
	if got := sweepRound(time.Second, []string{"one", "two"}, failing); got != "sweep: FAILED: two: boom" {
		t.Errorf("sweepRound = %q", got)
	}
}
