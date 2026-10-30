package mobile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

func TestJSONClaims(t *testing.T) {
	when := time.Date(2026, 10, 3, 1, 2, 3, 0, time.FixedZone("x", 3600))
	got, err := json.Marshal(jsonClaims(map[string]any{
		"ns": map[any]any{
			"portrait":    []byte{1, 2, 3},
			"birth_date":  cbor.Tag{Number: 1004, Content: "1990-01-02"},
			uint64(7):     []any{"a", []byte{0xff}},
			"issued":      when,
			"family_name": "Doe",
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"ns":{"7":["a","/w=="],"birth_date":"1990-01-02","family_name":"Doe","issued":"2026-10-03T00:02:03Z","portrait":"AQID"}}`
	if string(got) != want {
		t.Errorf("jsonClaims = %s\nwant          %s", got, want)
	}
}

// TestRecordWithoutClaims: a record written before claims were kept
// still loads, with none.
func TestRecordWithoutClaims(t *testing.T) {
	var r credentialRecord
	if err := json.Unmarshal([]byte(`{"id":"a","format":"dc+sd-jwt","credential":"x","holder_key_id":"k","received_at":"2026-10-01T00:00:00Z"}`), &r); err != nil {
		t.Fatal(err)
	}
	c, err := r.stored()
	if err != nil || c.Claims != nil || c.HolderKeyID != "k" {
		t.Errorf("stored = %+v, %v", c, err)
	}
	if _, err := (credentialRecord{Claims: json.RawMessage(`[1]`)}).stored(); err == nil {
		t.Error("a record whose claims aren't an object loaded")
	}
}

// TestRecordCredentialIdentifier: a credential's credential_identifier
// survives a record round trip, and a record written before it was kept
// loads with none.
func TestRecordCredentialIdentifier(t *testing.T) {
	r, err := recordOf(walletflow.StoredCredential{ID: "a", Format: "dc+sd-jwt", CredentialIdentifier: "pid-bob"})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back credentialRecord
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if got, err := back.stored(); err != nil || got.CredentialIdentifier != "pid-bob" {
		t.Errorf("stored = %+v, %v", got, err)
	}
	var old credentialRecord
	if err := json.Unmarshal([]byte(`{"id":"a","format":"dc+sd-jwt","credential":"x","holder_key_id":"k","received_at":"2026-10-01T00:00:00Z","grant_id":"g"}`), &old); err != nil {
		t.Fatal(err)
	}
	if got, err := old.stored(); err != nil || got.CredentialIdentifier != "" || got.GrantID != "g" {
		t.Errorf("an old record: %+v, %v", got, err)
	}
}

// TestRecordCopiesCorrelated: copies_correlated survives a record round
// trip, and a record written before it was kept loads as false.
func TestRecordCopiesCorrelated(t *testing.T) {
	r, err := recordOf(walletflow.StoredCredential{ID: "a", Format: "dc+sd-jwt", CopiesCorrelated: true})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back credentialRecord
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if got, err := back.stored(); err != nil || !got.CopiesCorrelated {
		t.Errorf("stored = %+v, %v", got, err)
	}
	var old credentialRecord
	if err := json.Unmarshal([]byte(`{"id":"a","format":"dc+sd-jwt","credential":"x","holder_key_id":"k","received_at":"2026-10-01T00:00:00Z"}`), &old); err != nil {
		t.Fatal(err)
	}
	if got, err := old.stored(); err != nil || got.CopiesCorrelated {
		t.Errorf("an old record: %+v, %v", got, err)
	}
}

// TestRecordCopyStatus: each copy's own status list entry and expiry
// survive a record round trip.
func TestRecordCopyStatus(t *testing.T) {
	until := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	c := walletflow.StoredCredential{ID: "a", Format: "dc+sd-jwt", Copies: []walletflow.CredentialCopy{
		{Credential: "x", HolderKeyID: "k1", StatusList: &statuslist.StatusListRef{Idx: 7, URI: "https://status.example/1"}, ValidUntil: until},
		{Credential: "y", HolderKeyID: "k2"},
	}}
	r, err := recordOf(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back credentialRecord
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, err := back.stored()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Copies, c.Copies) {
		t.Errorf("copies = %+v\nwant     %+v", got.Copies, c.Copies)
	}
}

func TestJSONClaims_NonFinite(t *testing.T) {
	got, err := json.Marshal(jsonClaims(map[string]any{"a": math.NaN(), "b": math.Inf(1), "c": float32(1.5)}))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"NaN","b":"+Inf","c":1.5}` {
		t.Errorf("jsonClaims = %s", got)
	}
}

// memStore is a CredentialStore holding records as given.
type memStore struct{ records map[string][]byte }

func (m memStore) Put(id string, r []byte) error { m.records[id] = r; return nil }
func (m memStore) Get(id string) ([]byte, error) { return m.records[id], nil }
func (m memStore) Durable() bool                 { return false }
func (m memStore) Delete(id string) error        { delete(m.records, id); return nil }
func (m memStore) CompareAndSwap(id string, expected, record []byte) ([]byte, error) {
	prev := m.records[id]
	switch {
	case !bytes.Equal(prev, expected):
	case len(record) == 0:
		delete(m.records, id)
	default:
		m.records[id] = record
	}
	return prev, nil
}
func (m memStore) List() ([]byte, error) {
	all := make([]json.RawMessage, 0, len(m.records))
	for _, r := range m.records {
		all = append(all, r)
	}
	return json.Marshal(all)
}

// TestCredentialStore_RefusesMismatchedRecords: a record stored under one
// ID but naming another, or two records with one ID, is refused — a
// deletion would otherwise remove another credential's holder key.
func TestCredentialStore_RefusesMismatchedRecords(t *testing.T) {
	ctx := context.Background()
	b := []byte(`{"id":"b","format":"dc+sd-jwt","credential":"x","holder_key_id":"kb","received_at":"2026-10-01T00:00:00Z"}`)
	mismatched := credentialStore{memStore{records: map[string][]byte{"a": b}}}
	if _, err := mismatched.Get(ctx, "a"); code(err) != CodePlatform {
		t.Errorf("Get of a record naming another ID = %v", err)
	}
	dup := credentialStore{memStore{records: map[string][]byte{"a": b, "c": b}}}
	if _, err := dup.List(ctx); code(err) != CodePlatform {
		t.Errorf("List with a duplicate ID = %v", err)
	}
	if c, err := (credentialStore{memStore{records: map[string][]byte{"b": b}}}).Get(ctx, "b"); err != nil || c.HolderKeyID != "kb" {
		t.Errorf("Get of a good record = %+v, %v", c, err)
	}
}

// TestClassify_MalformedLink: a link that doesn't parse is invalid_input,
// and isn't echoed — it may carry a pre-authorized code.
func TestClassify_MalformedLink(t *testing.T) {
	_, perr := url.Parse("openid-credential-offer://?credential_offer=\x7fsecret-code") //nolint:staticcheck // deliberately malformed
	if perr == nil {
		t.Fatal("the link parsed")
	}
	err := classify(fmt.Errorf("walletflow: credential offer: %w", perr))
	if code(err) != CodeInvalidInput || strings.Contains(err.Error(), "secret-code") {
		t.Errorf("classify = %v", err)
	}
}

func TestErrorCode(t *testing.T) {
	for in, want := range map[string]string{
		"invalid_grant": "invalid_grant", "access_denied": "access_denied", "": "",
		"invalid grant": "", "a]b": "", "x:y": "", strings.Repeat("a", 65): "",
	} {
		if got := errorCode(in); got != want {
			t.Errorf("errorCode(%q) = %q, want %q", in, got, want)
		}
	}
	if got := (&Error{Code: CodeProtocol, Detail: "invalid_grant", Message: "m"}).Error(); got != "[protocol:invalid_grant] m" {
		t.Errorf("Error() = %q", got)
	}
}
