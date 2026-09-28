package dcql

import (
	"encoding/json"
	"math/big"
)

// anyValueMatches reports whether one of selected equals one of want
// (§6.3's "the type and value of the claim both match exactly").
// Strings and booleans compare exactly. Integers compare by value
// across Go's numeric types, since a query decoded from JSON holds
// float64 while an mdoc element decoded from CBOR holds int64/uint64.
func anyValueMatches(selected, want []any) bool {
	for _, got := range selected {
		for _, w := range want {
			if valueEquals(got, w) {
				return true
			}
		}
	}
	return false
}

func valueEquals(got, want any) bool {
	switch w := want.(type) {
	case string:
		g, ok := got.(string)
		return ok && g == w
	case bool:
		g, ok := got.(bool)
		return ok && g == w
	}
	wn, ok := number(want)
	if !ok {
		return false
	}
	gn, ok := number(got)
	return ok && gn.Cmp(wn) == 0
}

// number converts the numeric types a claim or a Values entry holds —
// float64 or json.Number from JSON, int64 or uint64 from CBOR, int from
// a query built in Go — to an exact rational, or reports false for
// anything else.
func number(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	case uint64:
		return new(big.Rat).SetUint64(n), true
	case float64:
		r := new(big.Rat)
		return r, r.SetFloat64(n) != nil
	case json.Number:
		return new(big.Rat).SetString(n.String())
	default:
		return nil, false
	}
}
