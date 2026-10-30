package verifier_test

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/verifier"
)

// TestTransactions_ResultRetention: a completed request's result is
// reported for one Lifetime past the request's expiry and not after.
func TestTransactions_ResultRetention(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, func(c *verifier.TransactionsConfig) { c.Lifetime = time.Minute })
	start := f.now
	begun := f.begin("browser-binding-A", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
		t.Fatal(err)
	}
	f.now = start.Add(2*time.Minute - time.Second)
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionDone || view.Result == nil {
		t.Fatalf("Lookup within the retention = %+v, %v", view, err)
	}
	f.now = start.Add(2 * time.Minute)
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionExpired || view.Result != nil {
		t.Errorf("Lookup past the retention = %+v, %v; want expired, no result", view, err)
	}
}

// TestTransactions_Forget: Forget drops a completed request's result
// and closes it.
func TestTransactions_Forget(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-A", false)
	jwe := f.answer(begun, nil)
	if _, err := f.txs.HandleResponse(ctx, jwe); err != nil {
		t.Fatal(err)
	}
	if err := f.txs.Forget(ctx, begun.ID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A"); err != nil || view.Status != verifier.TransactionClosed || view.Result != nil {
		t.Errorf("Lookup after Forget = %+v, %v; want closed, no result", view, err)
	}
	if _, err := f.txs.HandleResponse(ctx, jwe); !errors.Is(err, verifier.ErrTransactionClosed) {
		t.Errorf("answer after Forget: %v, want ErrTransactionClosed", err)
	}
	// Served as for any closed request (see RequestObject).
	if _, err := f.txs.RequestObject(ctx, begun.ID); err != nil {
		t.Errorf("the request object after Forget: %v", err)
	}
	if err := f.txs.Forget(ctx, "unknown"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Forget of an unknown request: %v, want ErrTransactionUnknown", err)
	}
}

// TestTransactions_ForgetSameDevice: Forget of a same-device request
// awaiting its redirect retires the response_code with the result.
func TestTransactions_ForgetSameDevice(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-A", true)
	answered, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
	if err != nil {
		t.Fatal(err)
	}
	redirect, err := url.Parse(answered.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("response_code")
	if err := f.txs.Forget(ctx, begun.ID); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, err := f.txs.Redeem(ctx, code, "browser-binding-A"); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("Redeem after Forget: %v, want ErrTransactionUnknown", err)
	}
}

// TestTransactions_ForgetResultOnRead: under ForgetResultOnRead, the
// first read of a completed request — Lookup, Redeem or
// HandleDCAPIResponse — has its result, the store no longer does, and
// a later Lookup reports the request closed.
func TestTransactions_ForgetResultOnRead(t *testing.T) {
	ctx := context.Background()
	forgetting := func(c *verifier.TransactionsConfig) { c.ForgetResultOnRead = true }
	readOnce := func(t *testing.T, f *txFixture, id, binding string, first verifier.TransactionView, err error) {
		t.Helper()
		if err != nil || first.Status != verifier.TransactionDone || first.Result == nil {
			t.Fatalf("first read = %+v, %v; want the result", first, err)
		}
		if stored, _ := f.store.Get(ctx, id); stored.Result != nil || stored.Status != verifier.TransactionClosed {
			t.Errorf("stored after the first read: status %v, result %v; want closed, no result", stored.Status, stored.Result)
		}
		if view, err := f.txs.Lookup(ctx, id, binding); err != nil || view.Status != verifier.TransactionClosed || view.Result != nil {
			t.Errorf("Lookup after the first read = %+v, %v; want closed, no result", view, err)
		}
	}

	t.Run("cross-device", func(t *testing.T) {
		f := newTxFixture(t, forgetting)
		begun := f.begin("browser-binding-A", false)
		if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
			t.Fatal(err)
		}
		view, err := f.txs.Lookup(ctx, begun.ID, "browser-binding-A")
		readOnce(t, f, begun.ID, "browser-binding-A", view, err)
	})
	t.Run("same-device", func(t *testing.T) {
		f := newTxFixture(t, forgetting)
		begun := f.begin("browser-binding-A", true)
		answered, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
		if err != nil {
			t.Fatal(err)
		}
		redirect, err := url.Parse(answered.RedirectURI)
		if err != nil {
			t.Fatal(err)
		}
		view, err := f.txs.Redeem(ctx, redirect.Query().Get("response_code"), "browser-binding-A")
		readOnce(t, f, begun.ID, "browser-binding-A", view, err)
	})
	t.Run("Digital Credentials API", func(t *testing.T) {
		f := newTxFixture(t, forgetting)
		begun := f.beginDCAPI(testBinding)
		view, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin))
		readOnce(t, f, begun.ID, testBinding, view, err)
	})
}
