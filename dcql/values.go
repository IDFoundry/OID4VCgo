package dcql

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// anyValueMatches reports whether one of selected equals one of want
// (§6.3's "the type and value of the claim both match exactly").
// Strings and booleans compare exactly. Integers compare by value
// across Go's numeric types, since a query decoded from JSON holds
// float64 while an mdoc element decoded from CBOR holds int64/uint64.
// Each selected value is converted to JSON (jsonValue) once, not once
// per wanted value: a byte string's conversion costs its length.
func anyValueMatches(selected, want []any) bool {
	for _, got := range selected {
		got = jsonValue(got)
		for _, w := range want {
			if valueEquals(got, w) {
				return true
			}
		}
	}
	return false
}

// valueEquals reports whether got, already converted by jsonValue,
// equals want.
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
// float64 or json.Number from JSON, int64 or uint64 from CBOR, any of
// Go's numeric kinds from a query built in Go (isValuesElement accepts
// each) — to an exact rational, or reports false for anything else.
func number(v any) (*big.Rat, bool) {
	switch n := v.(type) {
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	case int8:
		return new(big.Rat).SetInt64(int64(n)), true
	case int16:
		return new(big.Rat).SetInt64(int64(n)), true
	case int32:
		return new(big.Rat).SetInt64(int64(n)), true
	case int64:
		return new(big.Rat).SetInt64(n), true
	case uint:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint8:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint16:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint32:
		return new(big.Rat).SetUint64(uint64(n)), true
	case uint64:
		return new(big.Rat).SetUint64(n), true
	case float32:
		r := new(big.Rat)
		return r, r.SetFloat64(float64(n)) != nil
	case float64:
		r := new(big.Rat)
		return r, r.SetFloat64(n) != nil
	case json.Number:
		return new(big.Rat).SetString(n.String())
	default:
		return nil, false
	}
}

// jsonValue is an mdoc element's CBOR value as JSON would hold it,
// which OpenID4VP §6.3 requires before matching ("the CBOR value used
// for matching MUST first be converted to JSON, following the advice
// given in Section 6.1 of [RFC8949]"): a tagged item becomes its
// content (a full-date, tag 1004, its string), a date-time its RFC
// 3339 string, and a byte string its base64url form without padding.
// Anything else, including every JSON value, is returned as it is.
func jsonValue(v any) any {
	switch x := v.(type) {
	case cbor.Tag:
		return jsonValue(x.Content)
	case time.Time:
		return x.UTC().Format(time.RFC3339Nano)
	case []byte:
		return base64.RawURLEncoding.EncodeToString(x)
	case cbor.ByteString:
		return base64.RawURLEncoding.EncodeToString([]byte(x))
	}
	return v
}
