package strictjson

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// fuzzNested is a struct target with nested struct, slice and map
// fields, so checkCase walks into each kind.
type fuzzNested struct {
	claims
	Items []inner            `json:"items"`
	ByKey map[string]inner   `json:"by_key"`
	Ptr   *inner             `json:"ptr"`
	Raw   json.RawMessage    `json:"raw"`
	Any   any                `json:"any"`
	Arr   [2]inner           `json:"arr"`
	Deep  map[string][]inner `json:"deep"`
}

// FuzzUnmarshal checks Unmarshal against encoding/json on arbitrary
// text: whatever it accepts, encoding/json accepts too and decodes to
// the same value; it refuses text that isn't UTF-8 and escapes of lone
// surrogates; and where encoding/json accepts what it refuses, the
// refusal is one of the cases it documents. checkText indexes past each
// backslash, trusting json.Valid, so no input may panic it.
func FuzzUnmarshal(f *testing.F) {
	for _, seed := range []string{
		`{"nonce":"a","aud":"b","kid":"k","Plain":"p","other":1}`,
		`{"nonce":"a","Nonce":"b"}`,
		`{"items":[{"kid":"a"},{"Kid":"b"}],"by_key":{"x":{"kid":"c"}}}`,
		`{"deep":{"a":[{"kid":"x","KID":"y"}]},"arr":[{"kid":"1"},{"kid":"2"}]}`,
		`{"raw":{"a":1,"a":2}}`,
		`{"any":{"x":[1,2,{"y":null}]},"ptr":{"kid":"p"}}`,
		`"\ud83d\ude00"`, `"\ud83d"`, `"\ude00\ud83d"`, `"\ud83d\\ude00"`, `"\ud83dA"`,
		`"\\u00"`, `"a\\"`, `"\u00e9\u2028"`, "\"\xff\"", `[1e400]`, `{"a":1}x`, `  {} `,
		`[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[1]]]]]]]]]]]]]]]]]]]]]]]]]]]]]`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		var strictAny, stdAny any
		strictErr := Unmarshal(data, &strictAny)
		stdErr := json.Unmarshal(data, &stdAny)
		if strictErr == nil {
			if stdErr != nil {
				t.Fatalf("strict accepted %q, encoding/json refused it: %v", data, stdErr)
			}
			if !reflect.DeepEqual(strictAny, stdAny) {
				t.Fatalf("strict decoded %q as %#v, encoding/json as %#v", data, strictAny, stdAny)
			}
			if !utf8.Valid(data) {
				t.Fatalf("strict accepted text that isn't UTF-8: %q", data)
			}
			if pos, lone := loneSurrogate(data); lone {
				t.Fatalf("strict accepted %q, with a lone surrogate escape at %d", data, pos)
			}
		} else if stdErr == nil {
			if !documentedRefusal(strictErr) {
				t.Fatalf("strict refused %q, which encoding/json accepts, with %v", data, strictErr)
			}
			if _, lone := loneSurrogate(data); strings.Contains(strictErr.Error(), "lone surrogate") && !lone {
				t.Fatalf("strict refused %q for a lone surrogate it doesn't have", data)
			}
		}

		var strictStruct, stdStruct fuzzNested
		if err := Unmarshal(data, &strictStruct); err == nil {
			if err := json.Unmarshal(data, &stdStruct); err != nil {
				t.Fatalf("strict accepted %q into a struct, encoding/json refused it: %v", data, err)
			}
			if !reflect.DeepEqual(strictStruct, stdStruct) {
				t.Fatalf("strict decoded %q as %+v, encoding/json as %+v", data, strictStruct, stdStruct)
			}
		}
		var m map[string][]inner
		_ = Unmarshal(data, &m)
		_ = Unmarshal(data, nil)
	})
}

// documentedRefusal reports whether err is one of the refusals
// Unmarshal adds to encoding/json's: text that isn't UTF-8, a lone
// surrogate, a duplicate member, or (into a struct) a case-folded
// member name.
func documentedRefusal(err error) bool {
	msg := err.Error()
	for _, s := range []string{"not valid UTF-8", "lone surrogate", "appears twice", "names are case-sensitive"} {
		if strings.Contains(msg, s) {
			return true
		}
	}
	return false
}

// loneSurrogate is a reference for checkText's surrogate rule, written
// as a scanner that tracks whether it's inside a string: it reports the
// offset of a \u escape of a surrogate that isn't a high one directly
// followed by an escaped low one, or a low one directly preceded by an
// escaped high one. data is valid JSON.
func loneSurrogate(data []byte) (int, bool) {
	inString := false
	pendingHigh := -1 // offset just past a high surrogate's escape
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			inString = c == '"'
			continue
		}
		switch c {
		case '"':
			if pendingHigh >= 0 {
				return pendingHigh, true
			}
			inString = false
			continue
		case '\\':
		default:
			if pendingHigh >= 0 {
				return pendingHigh, true
			}
			continue
		}
		i++
		if data[i] != 'u' {
			if pendingHigh >= 0 {
				return pendingHigh, true
			}
			continue
		}
		n, _ := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		start := i - 1
		i += 4
		switch {
		case n >= 0xd800 && n < 0xdc00:
			if pendingHigh >= 0 {
				return pendingHigh, true
			}
			pendingHigh = start
		case n >= 0xdc00 && n <= 0xdfff:
			if pendingHigh < 0 {
				return start, true
			}
			pendingHigh = -1
		default:
			if pendingHigh >= 0 {
				return pendingHigh, true
			}
		}
	}
	return 0, false
}
