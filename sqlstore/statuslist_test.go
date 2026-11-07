package sqlstore_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"errors"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/identifierlist"
	"github.com/idfoundry/oid4vcgo/issuer"
	"github.com/idfoundry/oid4vcgo/sqlstore"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/statuslist/statuslisttest"
)

const (
	statusListA = "https://issuer.example/statuslists/1"
	statusListB = "https://issuer.example/statuslists/2"
)

// The statuslist.IndexStore contract: a reservation is made once and
// never released, statuses round-trip, and an index never reserved is
// reported as such.
func TestStatusIndexStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().StatusIndices()

		if n, err := s.Reserved(ctx, statusListA); err != nil || n != 0 {
			t.Fatalf("Reserved of an unseen list = %d, %v", n, err)
		}
		for _, idx := range []uint64{0, 7, math.MaxInt64} {
			if err := s.Reserve(ctx, statusListA, idx); err != nil {
				t.Fatalf("Reserve(%d): %v", idx, err)
			}
		}
		if err := s.Reserve(ctx, statusListA, 7); !errors.Is(err, statuslist.ErrIndexTaken) {
			t.Errorf("Reserve of a reserved index = %v, want ErrIndexTaken", err)
		}
		// The same index of another list is another index.
		if err := s.Reserve(ctx, statusListB, 7); err != nil {
			t.Errorf("Reserve of another list's index: %v", err)
		}
		if n, err := s.Reserved(ctx, statusListA); err != nil || n != 3 {
			t.Errorf("Reserved = %d, %v; want 3", n, err)
		}

		if got, err := s.Status(ctx, statusListA, 7); err != nil || got != statuslist.StatusValid {
			t.Errorf("Status of a new reservation = %v, %v; want VALID", got, err)
		}
		if err := s.SetStatus(ctx, statusListA, 7, statuslist.StatusSuspended); err != nil {
			t.Fatal(err)
		}
		if err := s.SetStatus(ctx, statusListA, 0, 0xff); err != nil {
			t.Fatal(err)
		}
		if got, err := s.Status(ctx, statusListA, 7); err != nil || got != statuslist.StatusSuspended {
			t.Errorf("Status = %v, %v; want SUSPENDED", got, err)
		}
		if got, err := s.Status(ctx, statusListB, 7); err != nil || got != statuslist.StatusValid {
			t.Errorf("another list's Status = %v, %v; want VALID", got, err)
		}
		// Setting a status again, even to the same one, is no new reservation.
		if err := s.SetStatus(ctx, statusListA, 7, statuslist.StatusSuspended); err != nil {
			t.Errorf("SetStatus to the same status: %v", err)
		}

		for name, c := range map[string]struct {
			uri string
			idx uint64
		}{
			"unreserved index": {statusListA, 1}, "unseen list": {"https://issuer.example/statuslists/9", 0},
			"index above MaxInt64": {statusListA, math.MaxUint64}, "invalid UTF-8 uri": {"https://issuer.example/\xff", 0},
			"NUL in uri": {"https://issuer.example/\x00", 0},
		} {
			if err := s.SetStatus(ctx, c.uri, c.idx, statuslist.StatusInvalid); !errors.Is(err, statuslist.ErrIndexNotReserved) {
				t.Errorf("%s: SetStatus = %v, want ErrIndexNotReserved", name, err)
			}
			if got, err := s.Status(ctx, c.uri, c.idx); !errors.Is(err, statuslist.ErrIndexNotReserved) || got != statuslist.StatusInvalid {
				t.Errorf("%s: Status = %v, %v; want INVALID, ErrIndexNotReserved", name, got, err)
			}
		}
		for name, c := range map[string]struct {
			uri string
			idx uint64
		}{
			"index above MaxInt64": {statusListA, math.MaxInt64 + 1}, "invalid UTF-8 uri": {"https://issuer.example/\xff", 0},
			"NUL in uri": {"https://issuer.example/\x00", 0},
		} {
			if err := s.Reserve(ctx, c.uri, c.idx); err == nil || errors.Is(err, statuslist.ErrIndexTaken) {
				t.Errorf("%s: Reserve = %v, want it refused", name, err)
			}
		}
		if _, err := s.ReserveEach(ctx, statusListA, []uint64{4, math.MaxInt64 + 1}); err == nil {
			t.Error("ReserveEach of an index above MaxInt64 succeeded")
		}
		if _, err := s.ReserveEach(ctx, "https://issuer.example/\x00", []uint64{4}); err == nil {
			t.Error("ReserveEach of an unstorable uri succeeded")
		}
		if got, err := s.ReserveEach(ctx, statusListA, nil); err != nil || len(got) != 0 {
			t.Errorf("ReserveEach of no indices = %v, %v", got, err)
		}
		if n, err := s.Reserved(ctx, "https://issuer.example/\xff"); err != nil || n != 0 {
			t.Errorf("Reserved of an unstorable uri = %d, %v", n, err)
		}
		if n, err := s.Reserved(ctx, statusListA); err != nil || n != 3 {
			t.Errorf("Reserved after the refusals = %d, %v; want 3", n, err)
		}
		if got, err := s.Statuses(ctx, "https://issuer.example/\xff", 8); err != nil || len(got) != 8 {
			t.Errorf("Statuses of an unstorable uri = %v, %v; want 8 VALID", got, err)
		}
	})
}

func TestStatusIndexStoreSharedContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		statuslisttest.TestIndexStoreContract(t, func(*testing.T) statuslist.IndexStore { return e.db().StatusIndices() })
	})
}

// TestStatusIndexStoreReserveEachContention: concurrent ReserveEach
// and Reserve calls naming the same indices, several counted in one
// shard — so Postgres finds some of them deadlocked, and cancels one —
// all succeed, each index reserved by exactly one, and counted once.
func TestStatusIndexStoreReserveEachContention(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().StatusIndices()
		const callers, perShard = 32, 8
		var all []uint64
		for shard := range uint64(4) {
			for k := range uint64(perShard) {
				all = append(all, shard+32*k)
			}
		}
		var mu sync.Mutex
		counts := map[uint64]int{}
		var wg sync.WaitGroup
		for c := range callers {
			wg.Go(func() {
				var got []uint64
				if c%4 == 3 {
					for _, idx := range all {
						switch err := s.Reserve(ctx, statusListA, idx); {
						case err == nil:
							got = append(got, idx)
						case !errors.Is(err, statuslist.ErrIndexTaken):
							t.Errorf("Reserve: %v", err)
						}
					}
				} else {
					idxs := slices.Clone(all)
					mrand.New(mrand.NewPCG(uint64(c), 0)).Shuffle(len(idxs), func(i, j int) { idxs[i], idxs[j] = idxs[j], idxs[i] }) // #nosec G115 G404 -- a test's shuffle
					var err error
					if got, err = s.ReserveEach(ctx, statusListA, idxs[:len(idxs)/2+c%3]); err != nil {
						t.Errorf("ReserveEach: %v", err)
					}
				}
				mu.Lock()
				for _, idx := range got {
					counts[idx]++
				}
				mu.Unlock()
			})
		}
		wg.Wait()
		for idx, k := range counts {
			if k != 1 {
				t.Fatalf("index %d reserved by %d callers", idx, k)
			}
		}
		if len(counts) != len(all) {
			t.Fatalf("%d indices reserved, want %d", len(counts), len(all))
		}
		if n, err := s.Reserved(ctx, statusListA); err != nil || n != len(all) {
			t.Fatalf("Reserved = %d, %v; want %d", n, err, len(all))
		}
	})
}

// bigList is how many indices TestStatusIndexStoreDeleteBigList
// reserves: more than two of Delete's batches.
const bigList = 25000

// Delete deletes a list of many rows, over several writes, and a
// Delete that stopped part-way — after some of the rows, or after all
// of them but before the count — leaves the list counted, for another
// to finish. A list deleted is reserved afresh.
func TestStatusIndexStoreDeleteBigList(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		raw := e.location()()
		d, err := sqlstore.New(raw, e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		s := d.StatusIndices()
		exec := func(query string, args ...any) {
			t.Helper()
			if _, err := raw.ExecContext(ctx, inDialect(e.dialect, query), args...); err != nil {
				t.Fatal(err)
			}
		}
		// fill reserves every index of list A below bigList, a thousand
		// a statement: Postgres's count trigger slows down with each row
		// of one transaction.
		fill := func() {
			t.Helper()
			for from := 0; from < bigList; from += 1000 {
				exec("WITH RECURSIVE n(i) AS (SELECT CAST(? AS BIGINT) UNION ALL SELECT i + 1 FROM n WHERE i < ?) INSERT INTO oid4vc_status_indices (uri, idx) SELECT ?, i FROM n", from, from+999, statusListA)
			}
		}
		reserved := func(uri string, want int) {
			t.Helper()
			if n, err := s.Reserved(ctx, uri); err != nil || n != want {
				t.Fatalf("Reserved(%s) = %d, %v; want %d", uri, n, err, want)
			}
		}
		deleted := func() {
			t.Helper()
			if err := s.Delete(ctx, statusListA); err != nil {
				t.Fatal(err)
			}
			reserved(statusListA, 0)
			if _, err := s.Status(ctx, statusListA, bigList-1); !errors.Is(err, statuslist.ErrIndexNotReserved) {
				t.Fatalf("Status of a deleted index = %v, want ErrIndexNotReserved", err)
			}
			if n := countShards(t, e.dialect, raw, statusListA); n != 0 {
				t.Fatalf("a deleted list has %d count shards left", n)
			}
		}

		fill()
		if err := s.Reserve(ctx, statusListB, 3); err != nil {
			t.Fatal(err)
		}
		if err := s.SetStatus(ctx, statusListA, 7, statuslist.StatusInvalid); err != nil {
			t.Fatal(err)
		}
		reserved(statusListA, bigList)
		if n := countShards(t, e.dialect, raw, statusListA); n != 32 {
			t.Fatalf("a list of %d indices has %d count shards, want 32", bigList, n)
		}
		deleted()
		if got, err := s.Statuses(ctx, statusListA, bigList); err != nil || bytes.Count(got, []byte{0}) != bigList {
			t.Fatalf("Statuses of a deleted list: %v", err)
		}
		reserved(statusListB, 1)

		// Stopped after some of the rows.
		fill()
		exec("DELETE FROM oid4vc_status_indices WHERE uri = ? AND idx < ?", statusListA, bigList/2)
		reserved(statusListA, bigList)
		deleted()
		// Stopped after every row, before the count.
		fill()
		exec("DELETE FROM oid4vc_status_indices WHERE uri = ?", statusListA)
		reserved(statusListA, bigList)
		deleted()

		if err := s.Reserve(ctx, statusListA, 7); err != nil {
			t.Fatalf("Reserve in a deleted list: %v", err)
		}
		reserved(statusListA, 1)
		if got, err := s.Status(ctx, statusListA, 7); err != nil || got != statuslist.StatusValid {
			t.Fatalf("Status of an index reserved afresh = %v, %v; want VALID", got, err)
		}
		if err := s.Delete(ctx, "https://issuer.example/\xff"); err != nil {
			t.Fatalf("Delete of an unstorable uri: %v", err)
		}
	})
}

// Statuses has one entry per index of the list, VALID where none is
// reserved, and refuses a list with an index reserved beyond its size.
func TestStatusIndexStoreStatuses(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().StatusIndices()
		for idx, status := range map[uint64]statuslist.StatusType{0: statuslist.StatusInvalid, 3: statuslist.StatusValid, 9: statuslist.StatusSuspended, 15: 0x0f} {
			if err := s.Reserve(ctx, statusListA, idx); err != nil {
				t.Fatal(err)
			}
			if err := s.SetStatus(ctx, statusListA, idx, status); err != nil {
				t.Fatal(err)
			}
		}
		got, err := s.Statuses(ctx, statusListA, 16)
		if err != nil {
			t.Fatal(err)
		}
		want := []uint8{1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0x0f}
		if string(got) != string(want) {
			t.Errorf("Statuses = %v, want %v", got, want)
		}
		if got, err := s.Statuses(ctx, statusListB, 0); err != nil || len(got) != 0 {
			t.Errorf("Statuses of an empty list of no indices = %v, %v", got, err)
		}
		if _, err := s.Statuses(ctx, statusListA, -1); err == nil {
			t.Error("Statuses with a negative size = nil error")
		}
		// Index 15 is reserved with a status, index 3 VALID: each is
		// outside a list of fewer indices.
		for _, size := range []int{15, 8, 4} {
			if _, err := s.Statuses(ctx, statusListA, size); err == nil || !strings.Contains(err.Error(), "outside") {
				t.Errorf("Statuses(size %d) = %v, want an index outside it refused", size, err)
			}
		}
	})
}

// Of concurrent Reserves of one index, from separate handles as from
// separate processes, exactly one succeeds; the others find it taken.
func TestStatusIndexStoreConcurrentReserve(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		const n = 16
		stores := make([]*sqlstore.StatusIndexStore, n)
		for i := range stores {
			stores[i] = open().StatusIndices()
		}
		errs := make([]error, n)
		var wg sync.WaitGroup
		for i, s := range stores {
			wg.Go(func() { errs[i] = s.Reserve(ctx, statusListA, 42) })
		}
		wg.Wait()
		won := 0
		for _, err := range errs {
			switch {
			case err == nil:
				won++
			case !errors.Is(err, statuslist.ErrIndexTaken):
				t.Errorf("concurrent Reserve: %v", err)
			}
		}
		if won != 1 {
			t.Errorf("%d concurrent Reserves of one index succeeded, want 1", won)
		}
		if got, err := stores[0].Reserved(ctx, statusListA); err != nil || got != 1 {
			t.Errorf("Reserved = %d, %v; want 1", got, err)
		}
	})
}

// Reserved counts every reservation exactly, however many are made at
// once, from separate handles as from separate processes, and none of
// those that find their index taken: the count's shards add up.
func TestStatusIndexStoreConcurrentReserveCount(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		const workers, indices = 8, 200
		var won atomic.Int64
		var wg sync.WaitGroup
		for range workers {
			s := open().StatusIndices()
			wg.Go(func() {
				// Every worker tries every index, each in its own order.
				for _, i := range mrand.Perm(indices) {
					idx := uint64(i) // #nosec G115 -- small and positive
					switch err := s.Reserve(ctx, statusListA, idx); {
					case err == nil:
						won.Add(1)
					case !errors.Is(err, statuslist.ErrIndexTaken):
						t.Errorf("Reserve(%d): %v", idx, err)
						return
					}
				}
			})
		}
		wg.Wait()
		if won.Load() != indices {
			t.Fatalf("%d Reserves succeeded, want %d", won.Load(), indices)
		}
		if n, err := open().StatusIndices().Reserved(ctx, statusListA); err != nil || n != indices {
			t.Errorf("Reserved = %d, %v; want %d", n, err, indices)
		}
	})
}

// A store that couldn't answer never reports an index as unreserved.
func TestStatusIndexStoreOutageIsNotUnreserved(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		s := e.db().StatusIndices()
		e.closeAll()
		if err := s.Reserve(ctx, statusListA, 1); err == nil || errors.Is(err, statuslist.ErrIndexTaken) {
			t.Errorf("Reserve on a closed database = %v", err)
		}
		if _, err := s.Reserved(ctx, statusListA); err == nil {
			t.Error("Reserved on a closed database = nil error")
		}
		err := s.SetStatus(ctx, statusListA, 1, statuslist.StatusInvalid)
		requireOutage(t, "SetStatus", err, statuslist.ErrIndexNotReserved)
		_, err = s.Status(ctx, statusListA, 1)
		requireOutage(t, "Status", err, statuslist.ErrIndexNotReserved)
		if _, err := s.Statuses(ctx, statusListA, 8); err == nil {
			t.Error("Statuses on a closed database = nil error")
		}
	})
}

// A statuslist.Allocator on the DB's store hands out indices a second
// handle, as after a restart, never hands out again, and its
// Publisher serves the statuses set through either.
func TestStatusIndexStoreWithAllocator(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		lists := []statuslist.AllocatorList{{URI: statusListA, Size: 64}}
		first := &statuslist.Allocator{Lists: lists, Store: open().StatusIndices(), Bits: statuslist.Bits2}
		refs := map[statuslist.StatusListRef]bool{}
		for range 16 {
			ref, err := first.Allocate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			refs[ref] = true
		}
		restarted := &statuslist.Allocator{Lists: lists, Store: open().StatusIndices(), Bits: statuslist.Bits2}
		for range 16 {
			ref, err := restarted.Allocate(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if refs[ref] {
				t.Fatalf("index %d handed out twice", ref.Idx)
			}
			refs[ref] = true
		}
		// Filled to the default limit, half the list.
		if _, err := restarted.Allocate(ctx); !errors.Is(err, statuslist.ErrListsFull) {
			t.Errorf("Allocate past the fill limit = %v, want ErrListsFull", err)
		}

		want := map[statuslist.StatusListRef]statuslist.StatusType{}
		i := 0
		for ref := range refs {
			status := []statuslist.StatusType{statuslist.StatusValid, statuslist.StatusInvalid, statuslist.StatusSuspended}[i%3]
			i++
			if err := []*statuslist.Allocator{first, restarted}[i%2].SetStatus(ctx, ref, status); err != nil {
				t.Fatal(err)
			}
			want[ref] = status
		}
		for idx := uint64(0); idx < 64; idx++ {
			if ref := (statuslist.StatusListRef{Idx: idx, URI: statusListA}); !refs[ref] {
				want[ref] = statuslist.StatusValid
				if err := first.SetStatus(ctx, ref, statuslist.StatusInvalid); !errors.Is(err, statuslist.ErrIndexNotReserved) {
					t.Errorf("SetStatus of an index never handed out = %v", err)
				}
				break
			}
		}

		key, chain := statusListSigner(t)
		p := &statuslist.Publisher{URI: statusListA, Signer: key, Chain: chain, Statuses: restarted.Statuses(statusListA), Bits: statuslist.Bits2}
		token, err := p.Token(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		for ref, status := range want {
			got, _, err := statuslist.Check(string(token), &key.PublicKey, oid4vci.ES256, ref, statuslist.VerifyOptions{UnboundSigner: statuslist.AnyListSigner})
			if err != nil || got != status {
				t.Errorf("index %d: %v, %v; want %v", ref.Idx, got, err, status)
			}
		}
	})
}

// A database migrated by an earlier release, to version 3, migrates to
// the status index table with its records kept; until then,
// CheckSchema fails and the store reports an error, never an index
// unreserved.
func TestMigrateAddsStatusIndices(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d, err := sqlstore.New(e.location()(), e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlstore.MigrateTo(ctx, d, 3); err != nil {
			t.Fatal(err)
		}
		if err := d.Notifications().Issue(ctx, "n", issuer.NotificationRecord{}); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "0004_status_indices.sql") {
			t.Errorf("CheckSchema at version 3 = %v, want migration 0004 missing", err)
		}
		_, err = d.StatusIndices().Status(ctx, statusListA, 0)
		requireOutage(t, "Status before migration 0004", err, statuslist.ErrIndexNotReserved)

		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err != nil {
			t.Errorf("CheckSchema after Migrate: %v", err)
		}
		if _, err := d.Notifications().Get(ctx, "n"); err != nil {
			t.Errorf("a record from before the migration: %v", err)
		}
		if err := d.StatusIndices().Reserve(ctx, statusListA, 0); err != nil {
			t.Errorf("Reserve after migration: %v", err)
		}
	})
}

// Migration 0007 counts the indices reserved before it, and every
// reservation after it, but not a Reserve that finds its index taken.
func TestMigrateCountsReservedIndices(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		d, err := sqlstore.New(e.location()(), e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlstore.MigrateTo(ctx, d, 6); err != nil {
			t.Fatal(err)
		}
		s := d.StatusIndices()
		for _, idx := range []uint64{1, 5, 9} {
			if err := s.Reserve(ctx, statusListA, idx); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Reserve(ctx, statusListB, 2); err != nil {
			t.Fatal(err)
		}
		if err := s.SetStatus(ctx, statusListA, 5, statuslist.StatusInvalid); err != nil {
			t.Fatal(err)
		}

		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		reserved := func(uri string, want int) {
			t.Helper()
			if n, err := s.Reserved(ctx, uri); err != nil || n != want {
				t.Errorf("Reserved(%s) = %d, %v, want %d", uri, n, err, want)
			}
		}
		reserved(statusListA, 3)
		reserved(statusListB, 1)
		if err := s.Reserve(ctx, statusListA, 7); err != nil {
			t.Fatal(err)
		}
		if err := s.Reserve(ctx, statusListA, 9); !errors.Is(err, statuslist.ErrIndexTaken) {
			t.Fatalf("Reserve of a taken index = %v", err)
		}
		reserved(statusListA, 4)
		reserved(statusListB, 1)
		reserved("https://issuer.example/statuslists/3", 0)
		if got, err := s.Statuses(ctx, statusListA, 10); err != nil || string(got) != string([]uint8{0, 0, 0, 0, 0, 1, 0, 0, 0, 0}) {
			t.Errorf("Statuses after migration = %v, %v", got, err)
		}
	})
}

// Migration 0010 moves each list's count, kept by 0007, into its count
// shards, and counts every reservation after it in them. The table the
// count was kept in becomes a view summing the shards, which an older
// release reads its counts from, and whose Delete it refuses.
func TestMigrateShardsReservedCounts(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		raw := e.location()()
		d, err := sqlstore.New(raw, e.dialect, sqlstore.Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err := sqlstore.MigrateTo(ctx, d, 9); err != nil {
			t.Fatal(err)
		}
		s := d.StatusIndices()
		for _, idx := range []uint64{1, 5, 9, 33} {
			if err := s.Reserve(ctx, statusListA, idx); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Reserve(ctx, statusListB, 2); err != nil {
			t.Fatal(err)
		}
		if err := d.CheckSchema(ctx); err == nil || !strings.Contains(err.Error(), "0010_status_list_count_shards.sql") {
			t.Errorf("CheckSchema at version 9 = %v, want migration 0010 missing", err)
		}

		// Up to 0012, the last migration an older release could run beside.
		if err := sqlstore.MigrateTo(ctx, d, 12); err != nil {
			t.Fatal(err)
		}
		reserved := func(uri string, want int) {
			t.Helper()
			if n, err := s.Reserved(ctx, uri); err != nil || n != want {
				t.Errorf("Reserved(%s) = %d, %v, want %d", uri, n, err, want)
			}
		}
		reserved(statusListA, 4)
		reserved(statusListB, 1)
		for _, idx := range []uint64{7, 65} {
			if err := s.Reserve(ctx, statusListA, idx); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.Reserve(ctx, statusListA, 9); !errors.Is(err, statuslist.ErrIndexTaken) {
			t.Fatalf("Reserve of a taken index = %v", err)
		}
		reserved(statusListA, 6)
		reserved(statusListB, 1)
		// The moved count in shard 0, 7 in shard 7, 65 in shard 1.
		if n := countShards(t, e.dialect, raw, statusListA); n != 3 {
			t.Errorf("list A has %d count shards, want 3", n)
		}

		// An older release's statements.
		var n int64
		if err := raw.QueryRowContext(ctx, inDialect(e.dialect, "SELECT COALESCE((SELECT reserved FROM oid4vc_status_list_counts WHERE uri = ?), 0)"), statusListA).Scan(&n); err != nil || n != 6 {
			t.Errorf("an older release's Reserved = %d, %v; want 6", n, err)
		}
		if _, err := raw.ExecContext(ctx, inDialect(e.dialect, "DELETE FROM oid4vc_status_list_counts WHERE uri = ?"), statusListB); err == nil {
			t.Error("an older release's Delete of a list's count succeeded")
		}
		reserved(statusListB, 1)

		// 0013 drops the view; the counts stay in the shards.
		if err := d.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.ExecContext(ctx, "SELECT reserved FROM oid4vc_status_list_counts"); err == nil {
			t.Error("oid4vc_status_list_counts is still there after 0013")
		}
		reserved(statusListA, 6)
		reserved(statusListB, 1)

		if err := s.Delete(ctx, statusListA); err != nil {
			t.Fatal(err)
		}
		reserved(statusListA, 0)
		reserved(statusListB, 1)
	})
}

// countShards is how many count shards the list at uri has.
func countShards(t *testing.T, dialect sqlstore.Dialect, raw *sql.DB, uri string) int64 {
	t.Helper()
	var n int64
	if err := raw.QueryRowContext(context.Background(), inDialect(dialect, "SELECT COUNT(*) FROM oid4vc_status_list_count_shards WHERE uri = ?"), uri).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// inDialect is query, written with SQLite's placeholders, in dialect's.
func inDialect(dialect sqlstore.Dialect, query string) string {
	if dialect == sqlstore.Postgres {
		for i := 1; strings.Contains(query, "?"); i++ {
			query = strings.Replace(query, "?", "$"+strconv.Itoa(i), 1)
		}
	}
	return query
}

// statusListSigner is a Status List signing key and its certificate
// chain, under a CA of its own.
func statusListSigner(t *testing.T) (*ecdsa.PrivateKey, []*x509.Certificate) {
	t.Helper()
	now := time.Now()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Status CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Test Status List Signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, []*x509.Certificate{leaf}
}

// The statuslist.TokenStore contract, a list's version following the
// status changes of StatusIndices.
func TestStatusListTokenStoreContract(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		db := e.db()
		statuslisttest.TestTokenStoreContract(t, func(*testing.T) (statuslist.TokenStore, func(*testing.T, string)) {
			return db.StatusListTokens(), func(t *testing.T, uri string) { bumpStatus(t, db.StatusIndices(), uri) }
		})
	})
}

// bumpStatus changes a status of the list at uri: index 0's, between
// StatusValid and StatusInvalid.
func bumpStatus(t *testing.T, s *sqlstore.StatusIndexStore, uri string) {
	t.Helper()
	ctx := context.Background()
	if err := s.Reserve(ctx, uri, 0); err != nil && !errors.Is(err, statuslist.ErrIndexTaken) {
		t.Fatalf("Reserve: %v", err)
	}
	status, err := s.Status(ctx, uri, 0)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if err := s.SetStatus(ctx, uri, 0, status^statuslist.StatusInvalid); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
}

// A status set to what it already is leaves the list's version as it
// is; Delete forgets the list's tokens and version with its indices.
func TestStatusListTokenStoreVersionAndDelete(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		db := e.db()
		indices, tokens := db.StatusIndices(), db.StatusListTokens()
		bumpStatus(t, indices, statusListA)
		head, err := tokens.Head(ctx, statusListA, statuslist.FormJWT)
		if err != nil || head.Version != 1 {
			t.Fatalf("Head after one change = %+v, %v; want version 1", head, err)
		}
		if err := indices.SetStatus(ctx, statusListA, 0, statuslist.StatusInvalid); err != nil {
			t.Fatal(err)
		}
		if head, err := tokens.Head(ctx, statusListA, statuslist.FormJWT); err != nil || head.Version != 1 {
			t.Fatalf("Head after setting the same status = %+v, %v; want version 1", head, err)
		}
		now := time.UnixMilli(time.Now().UnixMilli())
		if err := tokens.Put(ctx, statusListA, statuslist.FormJWT, "a", statuslist.StoredToken{Bytes: []byte("t"), Version: 1, SignedAt: now, Exp: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := tokens.Put(ctx, statusListB, statuslist.FormJWT, "a", statuslist.StoredToken{Bytes: []byte("t"), SignedAt: now, Exp: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
		if err := indices.Delete(ctx, statusListA); err != nil {
			t.Fatal(err)
		}
		if head, err := tokens.Head(ctx, statusListA, statuslist.FormJWT); err != nil || head.Stored || head.Version != 0 {
			t.Fatalf("Head after Delete = %+v, %v; want nothing", head, err)
		}
		if head, err := tokens.Head(ctx, statusListB, statuslist.FormJWT); err != nil || !head.Stored {
			t.Fatalf("another list's Head after Delete = %+v, %v; want its token", head, err)
		}
	})
}

// Two replicas, each with its own handle on the database, serve one
// list through StatusListTokens: one signs, the other serves its token;
// a revocation through either replica's Allocator has one of them sign
// anew from its next check, and the token served shows it.
func TestStatusListTokensAcrossReplicas(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		ctx := context.Background()
		open := e.storage()
		lists := []statuslist.AllocatorList{{URI: statusListA, Size: 64}}
		key, chain := statusListSigner(t)
		now := time.UnixMilli(time.Now().UnixMilli())
		type replica struct {
			alloc *statuslist.Allocator
			pub   *statuslist.Publisher
			reads atomic.Int32
		}
		replicas := make([]*replica, 2)
		for i := range replicas {
			db := open()
			r := &replica{alloc: &statuslist.Allocator{Lists: lists, Store: db.StatusIndices()}}
			statuses := r.alloc.Statuses(statusListA)
			r.pub = &statuslist.Publisher{
				URI: statusListA, Signer: key, Chain: chain, TTL: time.Minute, Tokens: db.StatusListTokens(),
				Statuses: func(ctx context.Context) ([]uint8, error) { r.reads.Add(1); return statuses(ctx) },
				Now:      func() time.Time { return now },
			}
			replicas[i] = r
		}
		serve := func(i int) string {
			t.Helper()
			rec := httptest.NewRecorder()
			replicas[i].pub.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/s", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("replica %d: %d %s", i, rec.Code, rec.Body)
			}
			return rec.Body.String()
		}
		ref, err := replicas[0].alloc.Allocate(ctx)
		if err != nil {
			t.Fatal(err)
		}
		first := serve(0)
		if serve(1) != first || replicas[1].reads.Load() != 0 {
			t.Fatal("replica 1 didn't serve replica 0's token")
		}
		if err := replicas[1].alloc.SetStatus(ctx, ref, statuslist.StatusInvalid); err != nil {
			t.Fatal(err)
		}
		now = now.Add(statuslist.DefaultTokensCheck)
		second := serve(1)
		if second == first || serve(0) != second {
			t.Fatal("after a revocation: not one new token for both replicas")
		}
		if r0, r1 := replicas[0].reads.Load(), replicas[1].reads.Load(); r0+r1 != 2 {
			t.Fatalf("the statuses were read %d + %d times, want 2 in all", r0, r1)
		}
		got, _, err := statuslist.Check(second, &key.PublicKey, oid4vci.ES256, ref, statuslist.VerifyOptions{UnboundSigner: statuslist.AnyListSigner})
		if err != nil || got != statuslist.StatusInvalid {
			t.Fatalf("the token served after the revocation: %v, %v", got, err)
		}
	})
}

// identifierlist's Publishers share their tokens through
// StatusListTokens too: one replica signs, the other serves its token,
// and Invalidate has a replica sign anew for both.
func TestIdentifierListTokensAcrossReplicas(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e *env) {
		open := e.storage()
		key, chain := statusListSigner(t)
		now := time.UnixMilli(time.Now().UnixMilli())
		var reads [2]atomic.Int32
		pubs := make([]*identifierlist.Publisher, 2)
		for i := range pubs {
			pubs[i] = &identifierlist.Publisher{
				URI: "https://issuer.example/identifierlists/1", Signer: key, Chain: chain, TTL: time.Minute,
				Tokens:      open().StatusListTokens(),
				Identifiers: func(context.Context) ([][]byte, error) { reads[i].Add(1); return [][]byte{{1, 2, 3}}, nil },
				Now:         func() time.Time { return now },
			}
		}
		serve := func(i int) string {
			t.Helper()
			rec := httptest.NewRecorder()
			pubs[i].ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/l", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("replica %d: %d %s", i, rec.Code, rec.Body)
			}
			return rec.Body.String()
		}
		first := serve(0)
		if serve(1) != first || reads[1].Load() != 0 {
			t.Fatal("replica 1 didn't serve replica 0's token")
		}
		now = now.Add(time.Second)
		pubs[1].Invalidate()
		second := serve(1)
		now = now.Add(statuslist.DefaultTokensCheck)
		if second == first || serve(0) != second || reads[0].Load() != 1 {
			t.Fatal("after Invalidate: not one new token for both replicas")
		}
	})
}
