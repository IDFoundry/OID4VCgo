package cose

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// The decoder COSE structures go through before their signature is
// checked is bounded: an array or map past 4096 items, nesting past 16
// levels, and a duplicate map key are refused before anything is built
// from them.
func TestDecoderBounds(t *testing.T) {
	encode := func(v any) []byte {
		b, err := cbor.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	empties := func(n int) []any {
		out := make([]any, n)
		for i := range out {
			out[i] = map[string]any{}
		}
		return out
	}
	var nested any = 1
	for range 16 + 1 {
		nested = []any{nested}
	}
	var v any
	if err := decMode.Unmarshal(encode(empties(4096)), &v); err != nil {
		t.Errorf("an array at the bound: %v", err)
	}
	for name, data := range map[string][]byte{
		"array past the bound": encode(empties(4096 + 1)),
		"nested too deep":      encode(nested),
		// {"a": 1, "a": 2}
		"duplicate key": {0xa2, 0x61, 'a', 0x01, 0x61, 'a', 0x02},
	} {
		if err := decMode.Unmarshal(data, &v); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
}
