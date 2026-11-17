package verifier_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// setRow rewrites the stored record id of store, a codecStore, as a
// writer without the sealing key could: change sets JSON members of it.
func setRow(t *testing.T, store *codecStore, id string, change func(row map[string]any)) {
	t.Helper()
	store.mu.Lock()
	defer store.mu.Unlock()
	var row map[string]any
	if err := json.Unmarshal(store.rows[id], &row); err != nil {
		t.Fatal(err)
	}
	change(row)
	var err error
	if store.rows[id], err = json.Marshal(row); err != nil {
		t.Fatal(err)
	}
}

// The Request Object served at a request_uri is signed from the
// request's sealed fields, never served as stored: a store writer
// without the sealing key who puts another request's Request Object in
// a record doesn't get it served, and so can't have the holder's answer
// complete that other request (and its result released to another
// browser). A record without one — as a later version may write it —
// is still served.
func TestTransactions_RequestObjectNotServedFromStore(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	store := newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})
	cfg := verifier.TransactionsConfig{RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue", Verify: f.verify}
	txs, err := verifier.NewTransactions(f.v, store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	a, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-A-0123", SameDevice: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-B-0123"})
	if err != nil {
		t.Fatal(err)
	}
	objectB, err := txs.RequestObject(ctx, b.ID)
	if err != nil {
		t.Fatal(err)
	}

	for name, change := range map[string]func(map[string]any){
		"replaced": func(row map[string]any) { row["request_object"] = objectB },
		"removed":  func(row map[string]any) { delete(row, "request_object") },
	} {
		setRow(t, store, a.ID, change)
		served, err := txs.RequestObject(ctx, a.ID)
		if err != nil {
			t.Fatalf("%s: RequestObject: %v", name, err)
		}
		req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
			RequestObject: served, ClientID: f.v.ClientID(), VerifierTrust: wallet.NoVerifierTrust{},
		})
		if err != nil {
			t.Fatalf("%s: ParseAuthorizationRequest: %v", name, err)
		}
		if !strings.HasPrefix(req.State, a.ID+".") {
			t.Errorf("%s: A's request_uri serves state %q, not A's", name, req.State)
		}
	}
}

// redirectingStore is a TransactionStore that answers for the
// transaction from with the transaction to.
type redirectingStore struct {
	verifier.TransactionStore
	from, to string
}

func (s redirectingStore) target(id string) string {
	if id == s.from {
		return s.to
	}
	return id
}

func (s redirectingStore) Get(ctx context.Context, id string) (verifier.Transaction, error) {
	return s.TransactionStore.Get(ctx, s.target(id))
}

func (s redirectingStore) Update(ctx context.Context, id string, fn func(*verifier.Transaction) error) error {
	return s.TransactionStore.Update(ctx, s.target(id), fn)
}

// A store that answers for one transaction with another's record is
// refused, by every read and every update: otherwise one request would
// be served, answered or released as another.
func TestTransactions_StoreReturningAnotherTransaction(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	const binding = "browser-binding-0123456789"
	a, b := f.begin(binding, false), f.begin(binding, false)
	txs, err := verifier.NewTransactions(f.v, redirectingStore{f.store, a.ID, b.ID}, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txs.RequestObject(ctx, a.ID); err == nil || !strings.Contains(err.Error(), "asked for transaction") {
		t.Errorf("RequestObject: %v, want the store's record refused", err)
	}
	if _, err := txs.Lookup(ctx, a.ID, binding); err == nil || !strings.Contains(err.Error(), "asked for transaction") {
		t.Errorf("Lookup: %v, want the store's record refused", err)
	}
	if err := txs.Close(ctx, a.ID); err == nil || !strings.Contains(err.Error(), "asked for transaction") {
		t.Errorf("Close: %v, want the store's record refused", err)
	}
	if view, err := f.txs.Lookup(ctx, b.ID, binding); err != nil || view.Status != verifier.TransactionPending {
		t.Errorf("the other transaction: %+v, %v; want it pending, untouched", view, err)
	}
}

// queryDroppingStore is a TransactionStore that doesn't persist a
// query's values filters and trusted_authorities.
type queryDroppingStore struct{ verifier.TransactionStore }

func (s queryDroppingStore) Create(ctx context.Context, tx verifier.Transaction) error {
	credentials := slices.Clone(tx.Query.Credentials)
	for i := range credentials {
		credentials[i].TrustedAuthorities = nil
		credentials[i].Claims = slices.Clone(credentials[i].Claims)
		for j := range credentials[i].Claims {
			credentials[i].Claims[j].Values = nil
		}
	}
	tx.Query.Credentials = credentials
	return s.TransactionStore.Create(ctx, tx)
}

// A store that drops a claim's values filter would have the request
// accept a credential whose claim it was meant to refuse: Begin
// refuses it, naming Query. A store that keeps the query, re-encoded
// through JSON, is accepted.
func TestTransactions_StoreDroppingQueryValues(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	query := f.query
	query.Credentials = slices.Clone(query.Credentials)
	query.Credentials[0].Claims = []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}, Values: []any{"Jean"}}}
	const binding = "browser-binding-0123456789"

	txs, err := verifier.NewTransactions(f.v, queryDroppingStore{f.store}, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := txs.Begin(ctx, query, binding, false); err == nil || !strings.Contains(err.Error(), "Query") {
		t.Errorf("Begin: %v, want the store refused for dropping Query", err)
	}

	codecTxs, err := verifier.NewTransactions(f.v, newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)}), verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codecTxs.Begin(ctx, query, binding, false); err != nil {
		t.Errorf("Begin with a store that keeps the query: %v", err)
	}
	// An integer past 2^53 comes back from JSON rounded, as dcql.Query
	// documents: not taken as lost.
	query.Credentials[0].Claims = []dcql.ClaimsQuery{{Path: dcql.Path{dcql.PathKey("given_name")}, Values: []any{int64(1<<60 + 1)}}}
	if _, err := codecTxs.Begin(ctx, query, binding, false); err != nil {
		t.Errorf("Begin with a large integer value: %v", err)
	}
}
