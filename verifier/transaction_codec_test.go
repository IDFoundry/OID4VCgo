package verifier_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/verifier"
	"github.com/idfoundry/oid4vcgo/verifier/verifiertest"
)

// codecStore is a TransactionStore that keeps each transaction as the
// bytes TransactionCodec encodes it to, as a database-backed store
// would: nothing it gives back shares memory with what it was given.
type codecStore struct {
	codec  verifier.TransactionCodec
	mu     sync.Mutex
	rows   map[string][]byte
	byKey  map[string]string
	byCode map[string]string
}

func newCodecStore(codec verifier.TransactionCodec) *codecStore {
	return &codecStore{codec: codec, rows: map[string][]byte{}, byKey: map[string]string{}, byCode: map[string]string{}}
}

func (s *codecStore) Create(_ context.Context, tx verifier.Transaction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, used := s.rows[tx.ID]; used {
		return errors.New("ID in use")
	}
	return s.save(tx)
}

func (s *codecStore) save(tx verifier.Transaction) error {
	row, err := s.codec.Marshal(tx)
	if err != nil {
		return err
	}
	s.rows[tx.ID] = row
	if tx.KeyID != "" {
		s.byKey[tx.KeyID] = tx.ID
	}
	for code, id := range s.byCode {
		if id == tx.ID {
			delete(s.byCode, code)
		}
	}
	if tx.ResponseCodeHash != "" {
		s.byCode[tx.ResponseCodeHash] = tx.ID
	}
	return nil
}

func (s *codecStore) Get(_ context.Context, id string) (verifier.Transaction, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(id)
}

func (s *codecStore) get(id string) (verifier.Transaction, error) {
	row, ok := s.rows[id]
	if !ok {
		return verifier.Transaction{}, verifier.ErrTransactionUnknown
	}
	return s.codec.Unmarshal(row)
}

func (s *codecStore) Update(_ context.Context, id string, fn func(*verifier.Transaction) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.get(id)
	if err != nil {
		return err
	}
	if err := fn(&tx); err != nil {
		return err
	}
	tx.ID = id
	return s.save(tx)
}

func (s *codecStore) lookup(index map[string]string, key string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := index[key]; ok && key != "" {
		return id, nil
	}
	return "", verifier.ErrTransactionUnknown
}

func (s *codecStore) IDByKeyID(_ context.Context, kid string) (string, error) {
	return s.lookup(s.byKey, kid)
}

func (s *codecStore) IDByResponseCode(_ context.Context, codeHash string) (string, error) {
	return s.lookup(s.byCode, codeHash)
}

func testSealer(t *testing.T) verifier.TransactionSealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := verifier.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	return sealer
}

// TestTransactionCodec_StoreContract: a store that keeps transactions
// only as TransactionCodec's encoding, sealed or not, passes the store
// contract, which checks every field comes back as it was saved.
func TestTransactionCodec_StoreContract(t *testing.T) {
	t.Run("plain", func(t *testing.T) {
		verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore { return newCodecStore(verifier.TransactionCodec{}) })
	})
	t.Run("sealed", func(t *testing.T) {
		sealer := testSealer(t)
		verifiertest.TestTransactionStoreContract(t, func() verifier.TransactionStore {
			return newCodecStore(verifier.TransactionCodec{Sealer: sealer})
		})
	})
}

// TestTransactionCodec_Transactions: requests kept through the codec
// complete — the response decryption key comes back usable — in both
// flows.
func TestTransactionCodec_Transactions(t *testing.T) {
	ctx := context.Background()
	f := newTxFixture(t, nil)
	txs, err := verifier.NewTransactions(f.v, newCodecStore(verifier.TransactionCodec{Sealer: testSealer(t)}), verifier.TransactionsConfig{
		RequestURIBase: txBase, RedirectURI: "https://verifier.example.com/continue", Verify: f.verify,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.txs = txs
	cross := f.begin("browser-binding-cross-01", false)
	if _, err := f.txs.HandleResponse(ctx, f.answer(cross, nil)); err != nil {
		t.Fatalf("HandleResponse: %v", err)
	}
	view, err := f.txs.Lookup(ctx, cross.ID, "browser-binding-cross-01")
	if err != nil || view.Status != verifier.TransactionDone || view.Result.Credentials[0].Claims["given_name"] != "Jean" {
		t.Fatalf("Lookup = %+v, %v; want the result", view, err)
	}
	same := f.begin("browser-binding-same-001", true)
	answered, err := f.txs.HandleResponse(ctx, f.answer(same, nil))
	if err != nil || answered.RedirectURI == "" {
		t.Fatalf("same-device HandleResponse = %+v, %v; want a redirect_uri", answered, err)
	}
}

func marshalTestTransaction(t *testing.T, codec verifier.TransactionCodec, id string) ([]byte, verifier.Transaction) {
	t.Helper()
	f := newTxFixture(t, nil)
	begun := f.begin("browser-binding-codec-01", false)
	if _, err := f.txs.HandleResponse(context.Background(), f.answer(begun, nil)); err != nil {
		t.Fatalf("HandleResponse: %v", err)
	}
	tx, err := f.store.Get(context.Background(), begun.ID)
	if err != nil {
		t.Fatal(err)
	}
	tx.ID = id
	row, err := codec.Marshal(tx)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return row, tx
}

// TestTransactionCodec_Sealed: with a Sealer, the record carries
// neither the response decryption key nor the holder's claims, and a
// sealed field opens only in the transaction it was sealed in.
func TestTransactionCodec_Sealed(t *testing.T) {
	sealing := verifier.TransactionCodec{Sealer: testSealer(t)}
	row, tx := marshalTestTransaction(t, sealing, "tx-a")
	der, err := x509.MarshalPKCS8PrivateKey(tx.ResponseDecryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	encodedDER, _ := json.Marshal(der)
	raw, err := tx.ResponseDecryptionKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{raw, der, bytes.Trim(encodedDER, `"`), []byte("Jean")} {
		if bytes.Contains(row, secret) {
			t.Errorf("the sealed record carries %q", secret)
		}
	}
	if _, err := sealing.Unmarshal(row); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Another transaction's sealed fields, moved into this record, don't open.
	other, _ := marshalTestTransaction(t, sealing, "tx-b")
	var a, b map[string]any
	if err := json.Unmarshal(row, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(other, &b); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"response_decryption_key", "sealed_result"} {
		moved := map[string]any{}
		for k, v := range a {
			moved[k] = v
		}
		moved[field] = b[field]
		movedRow, _ := json.Marshal(moved)
		if _, err := sealing.Unmarshal(movedRow); err == nil {
			t.Errorf("tx-b's %s opened in tx-a's record", field)
		}
	}

	plainRow, _ := marshalTestTransaction(t, verifier.TransactionCodec{}, "tx-c")
	if _, err := sealing.Unmarshal(plainRow); err == nil {
		t.Error("a sealing codec read an unsealed record")
	}
	if _, err := (verifier.TransactionCodec{}).Unmarshal(row); err == nil {
		t.Error("a codec without a sealer read a sealed record")
	}
	if _, err := (verifier.TransactionCodec{Sealer: testSealer(t)}).Unmarshal(row); err == nil {
		t.Error("a record opened under another key")
	}
	if _, err := verifier.AESGCMSealer(make([]byte, 16)); err == nil {
		t.Error("AESGCMSealer took a 16-byte key")
	}
}

// TestTransactionCodec_RefusesWhatItDidntWrite: another version, an
// unknown field, a status a store never holds, no ID.
func TestTransactionCodec_RefusesWhatItDidntWrite(t *testing.T) {
	codec := verifier.TransactionCodec{}
	row, _ := marshalTestTransaction(t, codec, "tx-a")
	var fields map[string]any
	if err := json.Unmarshal(row, &fields); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(map[string]any){
		"version 2":       func(m map[string]any) { m["v"] = 2 },
		"unknown field":   func(m map[string]any) { m["sealer_hint"] = "x" },
		"status 0":        func(m map[string]any) { m["status"] = 0 },
		"status expired":  func(m map[string]any) { m["status"] = int(verifier.TransactionExpired) },
		"no id":           func(m map[string]any) { delete(m, "id") },
		"duplicate field": nil,
	} {
		changed := map[string]any{}
		for k, v := range fields {
			changed[k] = v
		}
		var data []byte
		if change == nil {
			data = append([]byte(`{"id":"x",`), row[1:]...)
		} else {
			change(changed)
			data, _ = json.Marshal(changed)
		}
		if _, err := codec.Unmarshal(data); err == nil {
			t.Errorf("%s: Unmarshal = nil error", name)
		}
	}
}

// TestTransactionCodec_MdocClaimsKeepTheirTypes: an mdoc's claims, as
// VerifyResponse gives them, come back with their CBOR types — an
// integer, a byte string, a full-date, a nested map — not as JSON's.
func TestTransactionCodec_MdocClaimsKeepTheirTypes(t *testing.T) {
	mf := newMdocVerifyFixture(t)
	elements := map[string]any{
		"age_in_years": 42, "portrait": []byte{0xff, 0xd8, 0xff}, "birth_date": cbor.Tag{Number: 1004, Content: "1990-01-02"},
		"driving_privileges": []any{map[string]any{"vehicle_category_code": "B"}},
	}
	mf.f = testmdoc.IssueWith(t, func(c *mdoc.Claims) {
		for name, value := range elements {
			c.NameSpaces["org.iso.18013.5.1"][name] = value
		}
		c.Status = &mdoc.StatusListRef{Idx: 7, URI: "https://issuer.example.com/sl"}
	})
	for _, name := range []string{"age_in_years", "portrait", "birth_date", "driving_privileges"} {
		mf.query.Credentials[0].Claims = append(mf.query.Credentials[0].Claims, dcql.ClaimsQuery{Path: dcql.Path{dcql.PathKey("org.iso.18013.5.1"), dcql.PathKey(name)}})
	}
	result, err := mf.verify(t, mf.nonce)
	if err != nil {
		t.Fatalf("VerifyResponse: %v", err)
	}
	for _, codec := range []verifier.TransactionCodec{{}, {Sealer: testSealer(t)}} {
		row, err := codec.Marshal(verifier.Transaction{ID: "tx", Query: mf.query, Status: verifier.TransactionDone, Result: &result})
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		got, err := codec.Unmarshal(row)
		if err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if !reflect.DeepEqual(*got.Result, result) {
			t.Errorf("result after a round trip (sealed %t):\n got %s\nwant %s", codec.Sealer != nil, describe(*got.Result), describe(result))
		}
	}
}

func describe(r verifier.VerifyResponseResult) string {
	var b strings.Builder
	for _, vc := range r.Credentials {
		fmt.Fprintf(&b, "%s: %#v status=%+v; ", vc.CredentialQueryID, vc.Claims, vc.MdocStatus)
	}
	return b.String()
}
