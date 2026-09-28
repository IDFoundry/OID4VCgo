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

// number converts a Go numeric value to an exact rational, or reports
// false for anything else.
func number(v any) (*big.Rat, bool) {
	r := new(big.Rat)
	switch n := v.(type) {
	case int:
		return r.SetInt64(int64(n)), true
	case int8:
		return r.SetInt64(int64(n)), true
	case int16:
		return r.SetInt64(int64(n)), true
	case int32:
		return r.SetInt64(int64(n)), true
	case int64:
		return r.SetInt64(n), true
	case uint:
		return r.SetUint64(uint64(n)), true
	case uint8:
		return r.SetUint64(uint64(n)), true
	case uint16:
		return r.SetUint64(uint64(n)), true
	case uint32:
		return r.SetUint64(uint64(n)), true
	case uint64:
		return r.SetUint64(n), true
	case float64:
		if r.SetFloat64(n) == nil {
			return nil, false
		}
		return r, true
	case float32:
		if r.SetFloat64(float64(n)) == nil {
			return nil, false
		}
		return r, true
	case json.Number:
		if _, ok := r.SetString(n.String()); !ok {
			return nil, false
		}
		return r, true
	default:
		return nil, false
	}
}
