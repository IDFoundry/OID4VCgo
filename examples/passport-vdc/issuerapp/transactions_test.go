package issuerapp

import (
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/passport"
)

func TestTransactions_CapsLivePassports(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	tx := newTransactions(func() time.Time { return now }, time.Minute, 2)
	for range 2 {
		if _, err := tx.put(passport.Evidence{}); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	if _, err := tx.put(passport.Evidence{}); !errors.Is(err, errTooManyTransactions) {
		t.Fatalf("third put: error = %v, want errTooManyTransactions", err)
	}
	now = now.Add(time.Minute) // both expire, freeing room
	if _, err := tx.put(passport.Evidence{}); err != nil {
		t.Fatalf("put after expiry: %v", err)
	}
}
