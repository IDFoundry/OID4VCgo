package statuslist

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// FuzzParseStatusClaim exercises ParseStatusClaim on a JSON "status"
// claim, the way a Verifier gets one out of a presented SD-JWT VC, and
// checks a parsed reference survives Claim's round trip.
func FuzzParseStatusClaim(f *testing.F) {
	f.Add([]byte(`{"status_list":{"idx":3,"uri":"https://issuer.example/statuslists/1"}}`))
	f.Add([]byte(`{"status_list":{"idx":1e300,"uri":"x"}}`))
	f.Add([]byte(`{"status_list":{"idx":-1,"uri":"x"}}`))
	f.Add([]byte(`{"status_list":[]}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		var status map[string]any
		if json.Unmarshal(data, &status) != nil {
			return
		}
		ref, err := ParseStatusClaim(status)
		if err != nil {
			return
		}
		raw, err := json.Marshal(ref.Claim())
		if err != nil {
			t.Fatalf("marshal Claim: %v", err)
		}
		var again map[string]any
		if err := json.Unmarshal(raw, &again); err != nil {
			t.Fatalf("unmarshal Claim: %v", err)
		}
		if back, err := ParseStatusClaim(again); err != nil || back != ref {
			t.Errorf("round trip of %+v = %+v, %v", ref, back, err)
		}
	})
}

// FuzzParseCWTStatusClaim is FuzzParseStatusClaim's CBOR counterpart,
// for an mdoc's CWT "status" claim.
func FuzzParseCWTStatusClaim(f *testing.F) {
	seed, err := cbor.Marshal(map[string]any{"status_list": map[string]any{"idx": 3, "uri": "https://issuer.example/statuslists/1"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{0xa1, 0x6b, 's', 't', 'a', 't', 'u', 's', '_', 'l', 'i', 's', 't', 0xf6})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var status map[string]interface{}
		if cbor.Unmarshal(data, &status) != nil {
			return
		}
		ref, err := ParseCWTStatusClaim(status)
		if err != nil {
			return
		}
		claim, err := ref.CWTStatusClaim()
		if err != nil {
			t.Fatalf("CWTStatusClaim(%+v): %v", ref, err)
		}
		raw, err := cbor.Marshal(claim)
		if err != nil {
			t.Fatalf("marshal CWTStatusClaim: %v", err)
		}
		var again map[string]interface{}
		if err := cbor.Unmarshal(raw, &again); err != nil {
			t.Fatalf("unmarshal CWTStatusClaim: %v", err)
		}
		if back, err := ParseCWTStatusClaim(again); err != nil || back != ref {
			t.Errorf("round trip of %+v = %+v, %v", ref, back, err)
		}
	})
}
