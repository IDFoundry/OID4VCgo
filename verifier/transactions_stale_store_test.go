package verifier_test

import (
	"context"
	"errors"
	"net/url"
	"sync"
	"testing"

	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// staleStore is a TransactionStore whose reads can lag its atomic
// Update, as a replicated or cached store's may: once frozen, Get
// returns the transaction as it was then, and IDByResponseCode keeps
// answering a code it once found. It makes deterministic the window two
// concurrent requests for one transaction both pass the checks made
// before Update.
type staleStore struct {
	*storage.VerifierTransactionStore
	mu     sync.Mutex
	frozen map[string]verifier.Transaction
	codes  map[string]string
}

func newStaleStore() *staleStore {
	return &staleStore{VerifierTransactionStore: storage.NewVerifierTransactionStore(), frozen: map[string]verifier.Transaction{}, codes: map[string]string{}}
}

// freeze makes Get return id's transaction as it is now.
func (s *staleStore) freeze(t *testing.T, id string) {
	t.Helper()
	tx, err := s.VerifierTransactionStore.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.frozen[id] = tx
}

func (s *staleStore) Get(ctx context.Context, id string) (verifier.Transaction, error) {
	s.mu.Lock()
	tx, ok := s.frozen[id]
	s.mu.Unlock()
	if ok {
		return tx, nil
	}
	return s.VerifierTransactionStore.Get(ctx, id)
}

func (s *staleStore) IDByResponseCode(ctx context.Context, codeHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.codes[codeHash]; ok {
		return id, nil
	}
	id, err := s.VerifierTransactionStore.IDByResponseCode(ctx, codeHash)
	if err == nil {
		s.codes[codeHash] = id
	}
	return id, err
}

// withStaleStore replaces f's Transactions with ones over a staleStore.
func (f *txFixture) withStaleStore(t *testing.T) *staleStore {
	t.Helper()
	s := newStaleStore()
	txs, err := verifier.NewTransactions(f.v, s, verifier.TransactionsConfig{
		RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue?x=1", Verify: f.verify,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.txs = txs
	return s
}

// A response code redeems once, even when the store's index still finds
// the transaction by it: Redeem's own check inside Update refuses the
// second.
func TestTransactions_RedeemOnceUnderStaleReads(t *testing.T) {
	f := newTxFixture(t, nil)
	f.withStaleStore(t)
	ctx := context.Background()
	begun := f.begin(testBinding, true)
	answered, err := f.txs.HandleResponse(ctx, f.answer(begun, nil))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(answered.RedirectURI)
	if err != nil {
		t.Fatal(err)
	}
	code := u.Query().Get("response_code")
	if view, err := f.txs.Redeem(ctx, code, testBinding); err != nil || view.Result == nil {
		t.Fatalf("first Redeem = %+v, %v", view, err)
	}
	if _, err := f.txs.Redeem(ctx, code, testBinding); !errors.Is(err, verifier.ErrTransactionUnknown) {
		t.Errorf("second Redeem = %v, want ErrTransactionUnknown", err)
	}
}

// A Digital Credentials API request completes once, even when a second
// valid answer read the transaction while it was still pending: the
// check inside Update refuses it, and the first answer's result stays.
func TestTransactions_DCAPIAnswerOnceUnderStaleReads(t *testing.T) {
	f := newTxFixture(t, nil)
	s := f.withStaleStore(t)
	ctx := context.Background()
	begun := f.beginDCAPI(testBinding)
	s.freeze(t, begun.ID)
	first, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin))
	if err != nil || first.Status != verifier.TransactionDone {
		t.Fatalf("first answer = %+v, %v", first, err)
	}
	if _, err := f.txs.HandleDCAPIResponse(ctx, begun.ID, testBinding, f.dcapiAnswer(begun, dcapiOrigin)); !errors.Is(err, verifier.ErrTransactionAnswered) {
		t.Errorf("second answer = %v, want ErrTransactionAnswered", err)
	}
}
