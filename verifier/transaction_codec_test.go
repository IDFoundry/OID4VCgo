package verifier_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/testmdoc"
	"github.com/idfoundry/oid4vcgo/sealing"
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

func testSealer(t *testing.T) sealing.Sealer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sealer, err := sealing.AESGCMSealer(key)
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
	// The anchor the issuer chain was verified to survives the store.
	if anchor, err := x509.ParseCertificate(view.Result.Credentials[0].IssuerAnchor); err != nil || anchor.Subject.CommonName != "tx issuer CA" {
		t.Fatalf("IssuerAnchor after the store = %v, %v; want the issuer CA", anchor, err)
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
	sealingCodec := verifier.TransactionCodec{Sealer: testSealer(t)}
	row, tx := marshalTestTransaction(t, sealingCodec, "tx-a")
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
	if _, err := sealingCodec.Unmarshal(row); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	// Another transaction's sealed fields, moved into this record, don't open.
	other, _ := marshalTestTransaction(t, sealingCodec, "tx-b")
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
		if _, err := sealingCodec.Unmarshal(movedRow); err == nil {
			t.Errorf("tx-b's %s opened in tx-a's record", field)
		}
	}

	// Nor does a record whose fields saying who may read it, or what it
	// asked for, were changed: the result would go to someone else.
	for name, change := range map[string]func(m map[string]any){
		"browser binding hash": func(m map[string]any) { m["browser_binding_hash"] = bytes.Repeat([]byte{1}, 32) },
		"owner":                func(m map[string]any) { m["owner"] = "another-verifier" },
		"same device":          func(m map[string]any) { m["same_device"] = true },
		"origin":               func(m map[string]any) { m["origin"] = "https://attacker.example" },
		// Nor one reopened, kept answerable longer, or answered under
		// another nonce, state or key.
		"status":     func(m map[string]any) { m["status"] = int(verifier.TransactionPending) },
		"expires_at": func(m map[string]any) { m["expires_at"] = "2999-01-01T00:00:00Z" },
		"nonce":      func(m map[string]any) { m["nonce"] = "another-nonce" },
		"state":      func(m map[string]any) { m["state"] = "another-state" },
		"kid":        func(m map[string]any) { m["kid"] = "another-kid" },
		"query": func(m map[string]any) {
			m["query"].(map[string]any)["credentials"].([]any)[0].(map[string]any)["id"] = "other"
		},
	} {
		var changed map[string]any
		if err := json.Unmarshal(row, &changed); err != nil {
			t.Fatal(err)
		}
		change(changed)
		changedRow, _ := json.Marshal(changed)
		if _, err := sealingCodec.Unmarshal(changedRow); err == nil || !strings.Contains(err.Error(), "open response_decryption_key") {
			t.Errorf("%s changed: Unmarshal = %v, want the sealed fields not to open", name, err)
		}
	}

	// The record reformatted, as a store keeping it as JSON may, still
	// opens.
	var reformatted bytes.Buffer
	if err := json.Indent(&reformatted, []byte(strings.Replace(string(row), `{"credentials":`, `{ "credentials" :`, 1)), "", "  "); err != nil {
		t.Fatal(err)
	}
	if _, err := sealingCodec.Unmarshal(reformatted.Bytes()); err != nil {
		t.Errorf("a reformatted sealed record: %v", err)
	}

	plainRow, _ := marshalTestTransaction(t, verifier.TransactionCodec{}, "tx-c")
	if _, err := sealingCodec.Unmarshal(plainRow); err == nil {
		t.Error("a sealingCodec codec read an unsealed record")
	}

	// A sealed record's result can't be replaced by a plaintext one,
	// written without the key, nor an unsealed record given a sealed one.
	var plain map[string]any
	if err := json.Unmarshal(plainRow, &plain); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]struct {
		codec     verifier.TransactionCodec
		record    map[string]any
		drop, add string
		value     any
	}{
		"plaintext result for a sealed one":    {sealingCodec, a, "sealed_result", "result", plain["result"]},
		"plaintext result beside a sealed one": {sealingCodec, a, "", "result", plain["result"]},
		"sealed result in an unsealed record":  {verifier.TransactionCodec{}, plain, "result", "sealed_result", a["sealed_result"]},
	} {
		changed := map[string]any{}
		for k, v := range change.record {
			changed[k] = v
		}
		delete(changed, change.drop)
		changed[change.add] = change.value
		changedRow, _ := json.Marshal(changed)
		if _, err := change.codec.Unmarshal(changedRow); err == nil {
			t.Errorf("%s: Unmarshal accepted it", name)
		}
	}
	if _, err := (verifier.TransactionCodec{}).Unmarshal(row); err == nil {
		t.Error("a codec without a sealer read a sealed record")
	}
	if _, err := (verifier.TransactionCodec{Sealer: testSealer(t)}).Unmarshal(row); err == nil {
		t.Error("a record opened under another key")
	}
}

// v1SealedRecord is testdata/transaction_codec_v1_sealed.json: a
// completed transaction as TransactionCodec version 1 (OID4VCgo
// v0.75.3) sealed it, under v1SealerKey.
const v1SealerKey = "76456737f50a4cf5bf467ea9b53be746a44da1e629f7c244fb4f719a00e50832"

func v1SealedRecord(t *testing.T) (verifier.TransactionCodec, map[string]any) {
	t.Helper()
	key, err := hex.DecodeString(v1SealerKey)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := sealing.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/transaction_codec_v1_sealed.json")
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	return verifier.TransactionCodec{Sealer: sealer}, record
}

// TestTransactionCodec_OpensVersion1: a record version 1 sealed, whose
// sealed fields weren't bound to its kid, nonce, state, status or
// expiry, still opens, with its result but without its Request Object,
// which it didn't bind either; written back, it's the current version,
// bound to them. Its expiry, given in another zone, is the same
// instant.
func TestTransactionCodec_OpensVersion1(t *testing.T) {
	codec, record := v1SealedRecord(t)
	if record["v"] != float64(1) {
		t.Fatalf("the fixture is version %v, want 1", record["v"])
	}
	data, _ := json.Marshal(record)
	tx, err := codec.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal of a version 1 record: %v", err)
	}
	if tx.Status != verifier.TransactionDone || tx.ResponseDecryptionKey == nil || tx.Result == nil || tx.Result.Credentials[0].Claims["given_name"] != "Jean" {
		t.Fatalf("version 1 record = %+v; want the completed transaction, its key and result", tx)
	}
	if record["request_object"] == "" || tx.RequestObject != "" {
		t.Errorf("version 1 record's Request Object = %.20q…, want it dropped", tx.RequestObject)
	}
	// Version 1 bound none of the fields version 2 added.
	record["nonce"] = "another-nonce"
	data, _ = json.Marshal(record)
	if _, err := codec.Unmarshal(data); err != nil {
		t.Errorf("a version 1 record with another nonce: %v (version 1 didn't bind it)", err)
	}
	// Nor does it open as a later version.
	for _, version := range []int{2, verifier.TransactionCodecVersion} {
		record["v"] = version
		data, _ = json.Marshal(record)
		if _, err := codec.Unmarshal(data); err == nil {
			t.Errorf("a version 1 record relabelled version %d opened", version)
		}
	}

	rewritten, err := codec.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var v2 map[string]any
	if err := json.Unmarshal(rewritten, &v2); err != nil {
		t.Fatal(err)
	}
	if v2["v"] != float64(verifier.TransactionCodecVersion) {
		t.Errorf("rewritten as version %v, want %d", v2["v"], verifier.TransactionCodecVersion)
	}
	expires, err := time.Parse(time.RFC3339Nano, v2["expires_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	v2["expires_at"] = expires.In(time.FixedZone("", -7*3600)).Format(time.RFC3339Nano)
	data, _ = json.Marshal(v2)
	if _, err := codec.Unmarshal(data); err != nil {
		t.Errorf("a rewritten record's expiry in another zone: %v", err)
	}
	v2["status"] = int(verifier.TransactionPending)
	data, _ = json.Marshal(v2)
	if _, err := codec.Unmarshal(data); err == nil {
		t.Error("a rewritten record reopened")
	}
}

// v2SealedRecord is testdata/transaction_codec_v2_sealed.json: a
// pending transaction as TransactionCodec version 2 (OID4VCgo v0.81.0)
// sealed it, with the Request Object it stored, under v1SealerKey.
func v2SealedRecord(t *testing.T) (verifier.TransactionCodec, map[string]any) {
	t.Helper()
	codec, _ := v1SealedRecord(t)
	data, err := os.ReadFile("testdata/transaction_codec_v2_sealed.json")
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	return codec, record
}

// TestTransactionCodec_OpensVersion2: a record version 2 sealed, whose
// sealed fields weren't bound to its Request Object, still opens, but
// without it: anyone who can write to the store could have put another
// request's there. Written back, it's the current version, and a
// Request Object put in it then no longer opens.
func TestTransactionCodec_OpensVersion2(t *testing.T) {
	codec, record := v2SealedRecord(t)
	if record["v"] != float64(2) || record["request_object"] == "" {
		t.Fatalf("the fixture is version %v, with request_object %v; want version 2 with one", record["v"], record["request_object"])
	}
	record["request_object"] = "another request's Request Object"
	data, _ := json.Marshal(record)
	tx, err := codec.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal of a version 2 record: %v", err)
	}
	if tx.ID != "tx-v2" || tx.Status != verifier.TransactionPending || tx.ResponseDecryptionKey == nil {
		t.Fatalf("version 2 record = %+v; want the pending transaction and its key", tx)
	}
	if tx.RequestObject != "" {
		t.Errorf("version 2 record's Request Object = %q, want it dropped", tx.RequestObject)
	}
	record["v"] = verifier.TransactionCodecVersion
	data, _ = json.Marshal(record)
	if _, err := codec.Unmarshal(data); err == nil {
		t.Errorf("a version 2 record relabelled version %d opened", verifier.TransactionCodecVersion)
	}

	rewritten, err := codec.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var current map[string]any
	if err := json.Unmarshal(rewritten, &current); err != nil {
		t.Fatal(err)
	}
	if current["v"] != float64(verifier.TransactionCodecVersion) {
		t.Errorf("rewritten as version %v, want %d", current["v"], verifier.TransactionCodecVersion)
	}
	current["request_object"] = "another request's Request Object"
	data, _ = json.Marshal(current)
	if _, err := codec.Unmarshal(data); err == nil {
		t.Error("a rewritten record opened with a Request Object put in it")
	}
}

// TestTransactionCodec_BindsRequestObject: a sealed record's Request
// Object is bound to it, so one replaced, removed or moved from another
// record leaves it unreadable. A codec without a sealer binds nothing,
// and reads the Request Object as stored.
func TestTransactionCodec_BindsRequestObject(t *testing.T) {
	sealed := verifier.TransactionCodec{Sealer: testSealer(t)}
	row, want := marshalTestTransaction(t, sealed, "tx-a")
	other, _ := marshalTestTransaction(t, sealed, "tx-b")
	var otherFields map[string]any
	if err := json.Unmarshal(other, &otherFields); err != nil {
		t.Fatal(err)
	}
	if got, err := sealed.Unmarshal(row); err != nil || got.RequestObject != want.RequestObject || got.RequestObject == "" {
		t.Fatalf("Unmarshal = %v; Request Object kept: %t", err, err == nil && got.RequestObject == want.RequestObject)
	}
	for _, c := range []struct {
		name   string
		change func(map[string]any)
	}{
		{"replaced", func(m map[string]any) { m["request_object"] = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln" }},
		{"another record's", func(m map[string]any) { m["request_object"] = otherFields["request_object"] }},
		{"removed", func(m map[string]any) { delete(m, "request_object") }},
	} {
		var fields map[string]any
		if err := json.Unmarshal(row, &fields); err != nil {
			t.Fatal(err)
		}
		c.change(fields)
		data, _ := json.Marshal(fields)
		if _, err := sealed.Unmarshal(data); err == nil {
			t.Errorf("%s: a sealed record opened", c.name)
		}
	}

	unsealed := verifier.TransactionCodec{}
	plain, _ := marshalTestTransaction(t, unsealed, "tx-c")
	var fields map[string]any
	if err := json.Unmarshal(plain, &fields); err != nil {
		t.Fatal(err)
	}
	const stored = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
	fields["request_object"] = stored
	data, _ := json.Marshal(fields)
	if got, err := unsealed.Unmarshal(data); err != nil || got.RequestObject != stored {
		t.Errorf("an unsealed record: %v; Request Object as stored: %t", err, err == nil && got.RequestObject == stored)
	}
}

// TestAESGCMSealer_Deprecated: the deprecated verifier.AESGCMSealer is
// sealing.AESGCMSealer, so a value one seals the other opens.
func TestAESGCMSealer_Deprecated(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	old, err := verifier.AESGCMSealer(key) //nolint:staticcheck // the deprecated forwarder under test
	if err != nil {
		t.Fatal(err)
	}
	current, err := sealing.AESGCMSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := old.Seal([]byte("x"), []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := current.Open(sealed, []byte("ad")); err != nil || string(got) != "x" {
		t.Errorf("sealing.AESGCMSealer didn't open verifier.AESGCMSealer's value: %q, %v", got, err)
	}
	if _, err := verifier.AESGCMSealer(make([]byte, 16)); err == nil { //nolint:staticcheck // as above
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
		"version 4":       func(m map[string]any) { m["v"] = 4 },
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
