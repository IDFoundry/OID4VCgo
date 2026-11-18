package strictjson

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type inner struct {
	Kid string `json:"kid"`
}

type claims struct {
	inner
	Nonce   string `json:"nonce"`
	Aud     string `json:"aud,omitempty"`
	Ignored string `json:"-"`
	Plain   string
}

func TestUnmarshal(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"nonce":"a","aud":"b","kid":"k","Plain":"p","other":1}`: true,
		`{"nonce":"a","Nonce":"b"}`:                               false,
		`{"NONCE":"a"}`:                                           false,
		`{"Kid":"k"}`:                                             false,
		`{"plain":"p"}`:                                           false,
		`[1]`:                                                     false,
	} {
		var c claims
		if err := Unmarshal([]byte(in), &c); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
	var c claims
	if err := Unmarshal([]byte(`{"nonce":"a","kid":"k"}`), &c); err != nil || c.Nonce != "a" || c.Kid != "k" {
		t.Errorf("decoded %+v, %v", c, err)
	}
	var m map[string]any
	if err := Unmarshal([]byte(`{"A":1,"a":2}`), &m); err != nil || len(m) != 2 {
		t.Errorf("a map: %v, %v", m, err)
	}
}

// Text that isn't UTF-8, and a lone surrogate escape, are refused (RFC
// 8259 §8.1, §8.2; RFC 7493 §2.1) rather than read as U+FFFD; a
// surrogate pair, escaped or not, decodes.
func TestUnmarshalText(t *testing.T) {
	for in, want := range map[string]string{
		`"\ud83d\ude00"`:   "\U0001f600",
		"\"\U0001f600\"":   "\U0001f600",
		`"a\\ud800"`:       `a\ud800`,
		`"\u00e9\n\u20ac"`: "\u00e9\n\u20ac",
	} {
		var s string
		if err := Unmarshal([]byte(in), &s); err != nil || s != want {
			t.Errorf("%s: %q, %v; want %q", in, s, err, want)
		}
	}
	for _, in := range []string{
		"\"\xff\"",
		"\"\xed\xa0\x80\"", // a surrogate in UTF-8
		"{\"n\xc3\":1}",
		`"\ud800"`,
		`"\udc00"`,
		`"\ud800x"`,
		`"\ud800\u0041"`,
		`"\ude00\ud83d"`,
		`{"\udfff":1}`,
		`["\ud83d\ude00","\ud83d"]`,
	} {
		var v any
		if err := Unmarshal([]byte(in), &v); err == nil {
			t.Errorf("%q: accepted as %q", in, v)
		}
	}
}

type outer struct {
	Claims  claims            `json:"claims"`
	List    []claims          `json:"list"`
	ByName  map[string]claims `json:"by_name"`
	Pointer *claims           `json:"pointer"`
	Raw     json.RawMessage   `json:"raw"`
}

// Duplicate members are refused at every depth, and a case-only match
// is refused in every struct reached through fields, slices, maps and
// pointers. A json.Unmarshaler (RawMessage) isn't looked into for case.
func TestUnmarshalNested(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"claims":{"nonce":"a"},"list":[{"nonce":"b"}],"by_name":{"x":{"nonce":"c"}},"pointer":{"nonce":"d"}}`: true,
		`{"nonce":"a","nonce":"b"}`:                     false,
		`{"claims":{"nonce":"a","nonce":"b"}}`:          false,
		`{"raw":{"x":1,"x":2}}`:                         false,
		`{"other":[{"k":1,"k":2}]}`:                     false,
		`{"claims":{"NONCE":"a"}}`:                      false,
		`{"list":[{"nonce":"a"},{"Nonce":"b"}]}`:        false,
		`{"by_name":{"x":{"Aud":"a"}}}`:                 false,
		`{"pointer":{"KID":"k"}}`:                       false,
		`{"raw":{"Nonce":"a","nonce":"b"}}`:             true,
		`{"other":{"Nonce":"a"},"Other":{"nonce":"b"}}`: true,
	} {
		var o outer
		if err := Unmarshal([]byte(in), &o); (err == nil) != ok {
			t.Errorf("%s: %v, want ok=%v", in, err, ok)
		}
	}
	var m map[string]any
	if err := Unmarshal([]byte(`{"a":{"b":1,"b":2}}`), &m); err == nil {
		t.Error("a map with a nested duplicate was accepted")
	}
}

// The bound counts each value, at any depth, and each member name: a
// document at it decodes, and one over it is refused, with
// ErrTooManyTokens.
func TestUnmarshalLimit(t *testing.T) {
	doc := []byte(`{"a":[1,{"b":null}],"c":"d"}`) // 9: 2 objects, 3 names, an array, 1, null, "d"
	var v any
	if err := UnmarshalLimit(doc, &v, 9); err != nil {
		t.Errorf("at the bound: %v", err)
	}
	if err := UnmarshalLimit(doc, &v, 8); !errors.Is(err, ErrTooManyTokens) {
		t.Errorf("over the bound: %v, want ErrTooManyTokens", err)
	}
	for _, bad := range []int{0, -1} {
		if err := UnmarshalLimit(doc, &v, bad); err == nil || errors.Is(err, ErrTooManyTokens) {
			t.Errorf("a bound of %d: %v, want it refused", bad, err)
		}
	}
	// Unmarshal's own: an array of DefaultMaxTokens-1 elements is
	// DefaultMaxTokens tokens.
	atBound := []byte("[" + strings.Repeat("0,", DefaultMaxTokens-2) + "0]")
	if err := Unmarshal(atBound, &v); err != nil {
		t.Errorf("DefaultMaxTokens tokens: %v", err)
	}
	overBound := []byte("[" + strings.Repeat("0,", DefaultMaxTokens-1) + "0]")
	if err := Unmarshal(overBound, &v); !errors.Is(err, ErrTooManyTokens) {
		t.Errorf("DefaultMaxTokens+1 tokens: %v, want ErrTooManyTokens", err)
	}
}

// A document over the bound is refused where the scan reaches it,
// having read about as many bytes as the bound's tokens take, however
// long the document is (DOS-1 of the 2026-11-18 audit).
func TestUnmarshalLimitStopsAtTheBound(t *testing.T) {
	const bound = 1000
	var members strings.Builder
	members.WriteString(`{"a":{"m0":0`)
	for i := 1; i < 1<<17; i++ {
		fmt.Fprintf(&members, `,"m%d":0`, i)
	}
	members.WriteString("}}")
	for name, doc := range map[string]string{
		"array":   `{"a":[` + strings.Repeat("0,", 1<<19) + `0]}`,
		"members": members.String(),
		"objects": `[` + strings.Repeat("{},", 1<<18) + `{}]`,
	} {
		s := scanner{data: []byte(doc), max: bound}
		if err := s.document(nil); !errors.Is(err, ErrTooManyTokens) {
			t.Errorf("%s: %v, want ErrTooManyTokens", name, err)
		}
		// No token here takes more than 8 bytes, with what follows it.
		if s.i > 8*bound {
			t.Errorf("%s: refused after %d of %d bytes, want at most %d", name, s.i, len(doc), 8*bound)
		}
	}
}

// One pass over the bytes: checking a document allocates nothing per
// token, where a json.Decoder.Token walk allocated for every one
// (DOS-1 of the 2026-11-18 audit).
func TestUnmarshalAllocations(t *testing.T) {
	doc := []byte(`{"nonce":"a","claims":[` + strings.Repeat(`0,"x",{},[],`, 1<<12) + `0]}`)
	var c claims
	allocs := testing.AllocsPerRun(10, func() {
		if err := Unmarshal(doc, &c); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 16 {
		t.Errorf("%v allocations for %d tokens, want a few", allocs, 4<<12)
	}
}
