package mobile

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
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
func (m memStore) Delete(id string) error        { delete(m.records, id); return nil }
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
