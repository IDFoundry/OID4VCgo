package verifier_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// A request its Verify configuration can't verify an answer to is
// refused when it's made, not left to fail every answer.
func TestTransactions_BeginChecksVerify(t *testing.T) {
	for name, tweak := range map[string]func(*verifier.TransactionsConfig){
		"no issuer keys":         func(c *verifier.TransactionsConfig) { c.Verify.IssuerKeys = nil },
		"no max key binding age": func(c *verifier.TransactionsConfig) { c.Verify.MaxKeyBindingAge = 0 },
	} {
		f := newTxFixture(t, tweak)
		if _, err := f.txs.Begin(context.Background(), f.query, "browser-binding-A-0123456789abcdef", false); err == nil || !strings.Contains(err.Error(), "Verify") {
			t.Errorf("%s: Begin = %v, want refused", name, err)
		}
	}
}

// failingStore fails to look a request up, as a store that's down
// would.
type failingStore struct {
	verifier.TransactionStore
	down bool
}

func (s *failingStore) IDByKeyID(ctx context.Context, kid string) (string, error) {
	if s.down {
		return "", errors.New("connection refused")
	}
	return s.TransactionStore.IDByKeyID(ctx, kid)
}

// The Verifier's own failure is a 500, not a 400 telling the Wallet its
// answer was refused.
func TestTransactions_StoreFaultIs500(t *testing.T) {
	f := newTxFixture(t, nil)
	store := &failingStore{TransactionStore: storage.NewVerifierTransactionStore()}
	txs, err := verifier.NewTransactions(f.v, store, verifier.TransactionsConfig{
		RequestURIBase: txBase,
		Verify:         verifier.VerifyResponseRequest{IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: x509.NewCertPool(), Revocation: certrevocation.NoCheck{}}, MaxKeyBindingAge: time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	f.txs = txs
	jwe := f.answer(f.begin("browser-binding-A", false), nil)
	resp := httptest.NewServer(txs.ResponseHandler())
	defer resp.Close()
	store.down = true
	r, err := http.PostForm(resp.URL, url.Values{"response": {jwe}})
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Body.Close()
	if r.StatusCode != http.StatusInternalServerError {
		t.Errorf("store down: %d, want 500", r.StatusCode)
	}
}
