package verifier_test

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/storage"
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

// requestURIStatus is the status RequestObjectHandler answers a GET of
// id's request_uri with.
func requestURIStatus(txs *verifier.Transactions, id string) int {
	rec := httptest.NewRecorder()
	txs.RequestObjectHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, txBase+"/"+id, nil))
	return rec.Code
}

// servedState is the state of the Request Object served at id's
// request_uri.
func servedState(t *testing.T, f *txFixture, txs *verifier.Transactions, id string) string {
	t.Helper()
	served, err := txs.RequestObject(context.Background(), id)
	if err != nil {
		t.Fatalf("RequestObject: %v", err)
	}
	req, err := wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{
		RequestObject: served, ClientID: f.v.ClientID(), VerifierTrust: wallet.NoVerifierTrust{},
	})
	if err != nil {
		t.Fatalf("ParseAuthorizationRequest: %v", err)
	}
	return req.State
}

// The Request Object served at a request_uri is the one Begin stored,
// bound into the sealed record: a store writer without the sealing key
// who puts another request's Request Object in a record, or removes
// it, leaves the record unreadable, answered 500, and so can't have
// the holder's answer complete that other request (and its result
// released to another browser).
func TestTransactions_RequestObjectBoundToSealedRecord(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	store := newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})
	cfg := verifier.TransactionsConfig{RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue", Verify: f.verify}
	txs, err := verifier.NewTransactions(f.v, store, cfg)
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

	for _, c := range []struct {
		name   string
		change func(row map[string]any)
	}{
		{"replaced", func(row map[string]any) { row["request_object"] = objectB }},
		{"removed", func(row map[string]any) { delete(row, "request_object") }},
	} {
		a, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-A-0123", SameDevice: true})
		if err != nil {
			t.Fatal(err)
		}
		if state := servedState(t, f, txs, a.ID); !strings.HasPrefix(state, a.ID+".") {
			t.Fatalf("%s: before the change, A's request_uri serves state %q", c.name, state)
		}
		setRow(t, store, a.ID, c.change)
		if served, err := txs.RequestObject(ctx, a.ID); err == nil {
			t.Errorf("%s: RequestObject served %.40q…, want the record refused", c.name, served)
		}
		if status := requestURIStatus(txs, a.ID); status != http.StatusInternalServerError {
			t.Errorf("%s: request_uri status %d, want 500", c.name, status)
		}
	}
}

// countingSigner counts its signatures.
type countingSigner struct {
	crypto.Signer
	n *atomic.Int64
}

func (s countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.n.Add(1)
	return s.Signer.Sign(r, digest, opts)
}

// countingTransactions is Transactions over store whose Verifier counts
// its signatures in the returned counter.
func countingTransactions(t *testing.T, f *txFixture, store verifier.TransactionStore) (*verifier.Transactions, *atomic.Int64) {
	t.Helper()
	n := new(atomic.Int64)
	deps := f.vdeps
	deps.Signer = countingSigner{deps.Signer, n}
	v, err := verifier.New(f.vcfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	txs, err := verifier.NewTransactions(v, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	return txs, n
}

// A request_uri GET signs nothing: whatever the store, every fetch is
// served the Request Object Begin signed and stored, however many
// requests are live. Another request is served its own.
func TestTransactions_RequestObjectNotSignedPerFetch(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	for _, c := range []struct {
		name  string
		store verifier.TransactionStore
	}{
		{"sealed", newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})},
		{"unsealed", newCodecStore(verifier.TransactionCodec{})},
		{"in memory", storage.NewVerifierTransactionStore()},
	} {
		txs, n := countingTransactions(t, f, c.store)
		a, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-A-0123"})
		if err != nil {
			t.Fatal(err)
		}
		b, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-B-0123"})
		if err != nil {
			t.Fatal(err)
		}
		stored, err := c.store.Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		before := n.Load()
		for range 10 {
			served, err := txs.RequestObject(ctx, a.ID)
			if err != nil {
				t.Fatal(err)
			}
			if served != stored.RequestObject {
				t.Fatalf("%s: a fetch served another Request Object than Begin stored", c.name)
			}
		}
		if other, err := txs.RequestObject(ctx, b.ID); err != nil || other == stored.RequestObject {
			t.Errorf("%s: another request was served %v, %v", c.name, other == stored.RequestObject, err)
		}
		if got := n.Load() - before; got != 0 {
			t.Errorf("%s: %d signatures for 11 fetches, want none", c.name, got)
		}
	}
}

// A record sealed before the Request Object was bound (version 2) is
// read without it: its Request Object is signed for each fetch from the
// fields the seal binds, so the one it holds, which a store writer may
// have replaced, is never served.
func TestTransactions_RequestObjectOfAnOlderSealedRecord(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	store := newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})
	txs, n := countingTransactions(t, f, store)
	a, err := txs.BeginWith(ctx, verifier.BeginOptions{Query: f.query, BrowserBinding: "browser-binding-of-A-0123"})
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
	store.mu.Lock()
	tx, err := store.codec.Unmarshal(store.rows[a.ID])
	if err == nil {
		store.rows[a.ID], err = verifier.MarshalTransactionVersion(store.codec, tx, 2)
	}
	store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	setRow(t, store, a.ID, func(row map[string]any) {
		if row["v"] != float64(2) || row["request_object"] != tx.RequestObject {
			t.Fatalf("the rewritten record is version %v, with request_object %t", row["v"], row["request_object"] == tx.RequestObject)
		}
		row["request_object"] = objectB
	})

	before := n.Load()
	for range 3 {
		if state := servedState(t, f, txs, a.ID); !strings.HasPrefix(state, a.ID+".") {
			t.Fatalf("A's request_uri serves state %q, not A's", state)
		}
	}
	if got := n.Load() - before; got != 3 {
		t.Errorf("%d signatures for 3 fetches of a version 2 record, want 3", got)
	}
}

// A sealed record is bound through its sealed fields: one stripped of
// them is refused, not opened with nothing checked, nor reported
// completed without its result.
func TestTransactions_RecordStrippedOfSealedFields(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	store := newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)})
	var err error
	if f.txs, err = verifier.NewTransactions(f.v, store, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify}); err != nil {
		t.Fatal(err)
	}
	const binding = "browser-binding-0123456789"
	for name, fields := range map[string][]string{
		"without its result":                   {"sealed_result"},
		"without its result or decryption key": {"sealed_result", "response_decryption_key"},
	} {
		begun := f.begin(binding, false)
		if _, err := f.txs.HandleResponse(ctx, f.answer(begun, nil)); err != nil {
			t.Fatalf("%s: HandleResponse: %v", name, err)
		}
		setRow(t, store, begun.ID, func(row map[string]any) {
			for _, field := range fields {
				delete(row, field)
			}
		})
		if view, err := f.txs.Lookup(ctx, begun.ID, binding); err == nil {
			t.Errorf("a completed record %s: Lookup = %+v, want it refused", name, view)
		}
	}
	pending := f.begin(binding, false)
	setRow(t, store, pending.ID, func(row map[string]any) { delete(row, "response_decryption_key") })
	if _, err := f.txs.RequestObject(ctx, pending.ID); err == nil {
		t.Error("a pending record without its decryption key: its Request Object was served")
	}
}

// unreadableStore is a TransactionStore whose reads fail.
type unreadableStore struct{ verifier.TransactionStore }

func (unreadableStore) Get(context.Context, string) (verifier.Transaction, error) {
	return verifier.Transaction{}, errors.New("store unavailable")
}

// A request_uri whose store fails is answered 500, as the response
// endpoint answers, not 404 as for an unknown request.
func TestRequestObjectHandler_StoreFailureIsAServerError(t *testing.T) {
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-0123456789", false)
	txs, err := verifier.NewTransactions(f.v, unreadableStore{f.store}, verifier.TransactionsConfig{RequestURIBase: txBase, Verify: f.verify})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	txs.RequestObjectHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, txBase+"/"+begun.ID, nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
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
