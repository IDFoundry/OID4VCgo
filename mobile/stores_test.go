package mobile

import (
	"encoding/json"
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
