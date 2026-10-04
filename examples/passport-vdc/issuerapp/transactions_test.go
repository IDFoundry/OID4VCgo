package issuerapp

import (
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

var testConfigIDs = []string{MdocConfigurationID, SDJWTConfigurationID}

func newTestTransactions(now *time.Time, limit int) *transactions {
	return newTransactions(func() time.Time { return *now }, time.Minute, time.Hour, limit)
}

func mustPut(t *testing.T, tx *transactions) (id, code string) {
	t.Helper()
	id, code, err := tx.put(passport.Evidence{}, testConfigIDs, false, false)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if len(code) != 6 {
		t.Fatalf("confirmation code %q isn't six digits", code)
	}
	return id, code
}

func TestTransactions_CapsLivePassports(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 2)
	mustPut(t, tx)
	mustPut(t, tx)
	if _, _, err := tx.put(passport.Evidence{}, testConfigIDs, false, false); !errors.Is(err, errTooManyTransactions) {
		t.Fatalf("third put: error = %v, want errTooManyTransactions", err)
	}
	now = now.Add(time.Minute) // both expire, freeing room
	mustPut(t, tx)
}

// TestTransactions_ClaimedOnce checks only the first approval with the
// right code claims a transaction, after which it can't start another.
func TestTransactions_ClaimedOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 10)
	id, code := mustPut(t, tx)

	if err := tx.claim(id, "000000"+"x"); !errors.Is(err, errWrongCode) {
		t.Fatalf("claim with a wrong code: error = %v, want errWrongCode", err)
	}
	if _, err := tx.unclaimed(id); err != nil {
		t.Fatalf("a wrong code claimed the transaction: %v", err)
	}
	if err := tx.claim(id, code); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if _, err := tx.unclaimed(id); !errors.Is(err, errAlreadyRedeemed) {
		t.Errorf("unclaimed after claim: error = %v, want errAlreadyRedeemed", err)
	}
	if err := tx.claim(id, code); !errors.Is(err, errAlreadyRedeemed) {
		t.Errorf("second claim: error = %v, want errAlreadyRedeemed", err)
	}
}

// TestTransactions_WrongCodesVoid checks maxCodeFailures wrong codes
// drop the transaction, so the code can't be guessed.
func TestTransactions_WrongCodesVoid(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 10)
	id, code := mustPut(t, tx)
	wrong := "x" + code[1:]
	for i := 1; i < maxCodeFailures; i++ {
		if err := tx.claim(id, wrong); !errors.Is(err, errWrongCode) {
			t.Fatalf("wrong code %d: error = %v, want errWrongCode", i, err)
		}
	}
	if err := tx.claim(id, wrong); !errors.Is(err, errTooManyWrongCodes) {
		t.Fatalf("wrong code %d: error = %v, want errTooManyWrongCodes", maxCodeFailures, err)
	}
	if err := tx.claim(id, code); !errors.Is(err, errNoTransaction) {
		t.Errorf("right code after voiding: error = %v, want errNoTransaction", err)
	}
}

// TestTransactions_IssuesEachCredentialOnce checks a claimed transaction
// issues each offered configuration once (a failed issue can be
// retried), and is dropped once all are issued.
func TestTransactions_IssuesEachCredentialOnce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 10)
	id, code := mustPut(t, tx)

	if _, _, err := tx.reserve(id, MdocConfigurationID); !errors.Is(err, errNoTransaction) {
		t.Fatalf("reserve before claim: error = %v, want errNoTransaction", err)
	}
	if err := tx.claim(id, code); err != nil {
		t.Fatalf("claim: %v", err)
	}

	if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
		t.Fatalf("reserve mdoc: %v", err)
	}
	tx.release(id, MdocConfigurationID) // issuing failed: retryable
	if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
		t.Fatalf("reserve mdoc after release: %v", err)
	}
	tx.done(id)
	if _, _, err := tx.reserve(id, MdocConfigurationID); !errors.Is(err, errAlreadyIssued) {
		t.Fatalf("reserve mdoc again: error = %v, want errAlreadyIssued", err)
	}
	if _, _, err := tx.reserve(id, "unoffered"); !errors.Is(err, errNotOffered) {
		t.Errorf("reserve an unoffered configuration: error = %v, want it refused", err)
	}

	if _, _, err := tx.reserve(id, SDJWTConfigurationID); err != nil {
		t.Fatalf("reserve sd-jwt: %v", err)
	}
	tx.done(id)
	tx.mu.Lock()
	_, held := tx.items[id]
	tx.mu.Unlock()
	if held {
		t.Error("the passport is still held after every credential was issued")
	}
}

// TestTransactions_KeepForRefresh checks a kept passport is issued again
// on each request, kept for keepFor (plus keepMargin) after its first
// credential, listed while kept, and dropped by forget; and that one not
// kept after all (dontKeep) is issued once.
func TestTransactions_KeepForRefresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTestTransactions(&now, 10)
	id, code, err := tx.put(passport.Evidence{}, testConfigIDs, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.claim(id, code); err != nil {
		t.Fatal(err)
	}
	if len(tx.kept()) != 0 {
		t.Error("listed as kept before its first credential")
	}
	now = now.Add(30 * time.Second) // within the transaction lifetime
	for range 3 {
		if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
			t.Fatalf("reserve a kept credential: %v", err)
		}
		tx.done(id)
	}
	kept := tx.kept()
	if len(kept) != 1 || kept[0].issued != 3 || !kept[0].until.Equal(now.Add(time.Hour+keepMargin)) {
		t.Fatalf("kept = %+v, want one, 3 issued, until keepFor+keepMargin after the first", kept)
	}
	if kept[0].ref == id || kept[0].ref != keptRef(id) {
		t.Errorf("kept ref = %q, want keptRef(id), not the ID", kept[0].ref)
	}

	now = kept[0].until.Add(-time.Second)
	if _, _, err := tx.reserve(id, SDJWTConfigurationID); err != nil {
		t.Fatalf("reserve just before the deadline: %v", err)
	}
	now = kept[0].until
	if _, _, err := tx.reserve(id, SDJWTConfigurationID); !errors.Is(err, errNoTransaction) {
		t.Errorf("reserve at the deadline: error = %v, want errNoTransaction", err)
	}
	if len(tx.items) != 0 || len(tx.kept()) != 0 {
		t.Error("the passport is still held after its deadline")
	}

	id, code, _ = tx.put(passport.Evidence{}, testConfigIDs, false, true)
	_ = tx.claim(id, code)
	if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
		t.Fatal(err)
	}
	tx.forget(id)
	tx.forget(id)
	if _, _, err := tx.reserve(id, MdocConfigurationID); !errors.Is(err, errNoTransaction) {
		t.Errorf("reserve after forget: error = %v, want errNoTransaction", err)
	}

	id, code, _ = tx.put(passport.Evidence{}, testConfigIDs, false, true)
	_ = tx.claim(id, code)
	tx.dontKeep(id)
	if tx.keeps(id) {
		t.Error("keeps after dontKeep")
	}
	if _, _, err := tx.reserve(id, MdocConfigurationID); err != nil {
		t.Fatal(err)
	}
	tx.done(id)
	if _, _, err := tx.reserve(id, MdocConfigurationID); !errors.Is(err, errAlreadyIssued) {
		t.Errorf("reserve again after dontKeep: error = %v, want errAlreadyIssued", err)
	}
}
