package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"unicode/utf16"
)

// The non-ASCII names below are written as UTF-8 bytes, and the JSON
// escapes in documents as ~u (u, below), so that no tool normalizing
// the source's text changes them.
const (
	kelvin    = "\xe2\x84\xaa"     // KELVIN SIGN, which folds with k and K
	longS     = "\xc5\xbf"         // LATIN SMALL LETTER LONG S, which folds with s and S
	sharpS    = "\xc3\x9f"         // ß, which folds with ẞ
	capSharpS = "\xe1\xba\x9e"     // ẞ
	dotI      = "\xc4\xb0"         // İ, which folds with nothing
	dotlessI  = "\xc4\xb1"         // ı, which folds with nothing
	emoji     = "\xf0\x9f\x98\x80" // U+1F600, outside the BMP
	romanXII  = "\xe2\x85\xab"     // Ⅻ, which folds with ⅻ
	romanxii  = "\xe2\x85\xbb"     // ⅻ
	eAcute    = "\xc3\xa9"         // é
	EAcute    = "\xc3\x89"         // É
)

// u replaces each ~u in s with a backslash and u, making a JSON \u
// escape.
func u(s string) string { return strings.ReplaceAll(s, "~u", `\`+"u") }

// diffFolds has fields whose names fold to one another under Unicode's
// simple case folding: KELVIN SIGN with k, LONG S with s, the sharp s
// with its capital, Roman numerals, and two fields differing only in
// case. It's built with reflect so its tags hold those names' bytes.
var diffFolds = reflect.StructOf([]reflect.StructField{
	{Name: "Kelvin", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + kelvin + `"`)},
	{Name: "LongS", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + longS + `"`)},
	{Name: "Sharp", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + sharpS + `"`)},
	{Name: "DotI", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + dotI + `"`)},
	{Name: "Emoji", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + emoji + `"`)},
	{Name: "Roman", Type: reflect.TypeFor[string](), Tag: reflect.StructTag(`json:"` + romanxii + `"`)},
	{Name: "Lower", Type: reflect.TypeFor[string](), Tag: `json:"a"`},
	{Name: "Upper", Type: reflect.TypeFor[string](), Tag: `json:"A"`},
})

// newOf returns a new pointer to a zero t.
func newOf(t reflect.Type) func() any {
	return func() any { return reflect.New(t).Interface() }
}

// diffNode is a recursive type, through a slice, a pointer and a map.
type diffNode struct {
	Name string               `json:"name"`
	Kids []diffNode           `json:"kids"`
	Next *diffNode            `json:"next"`
	ByID map[string]*diffNode `json:"by_id"`
}

// diffEmbedded embeds a struct through a pointer, shadows one of its
// names with a field differing only in case, and holds kinds the scan
// treats differently: a *json.RawMessage, an array, a map of maps, an
// interface and a json.Number.
type diffEmbedded struct {
	*inner
	KID   string                       `json:"KID"`
	Raw   *json.RawMessage             `json:"raw"`
	Arr   [1]inner                     `json:"arr"`
	M     map[string]map[string]inner  `json:"m"`
	Iface any                          `json:"iface"`
	Num   json.Number                  `json:"num"`
	Ptrs  []*map[string][]diffCustom   `json:"ptrs"`
	Text  map[string]diffTextUnmarshal `json:"text"`
}

// diffCustom has its own UnmarshalJSON, so its members aren't checked.
type diffCustom struct {
	Kid string `json:"kid"`
	Raw []byte
}

func (c *diffCustom) UnmarshalJSON(b []byte) error {
	c.Raw = append([]byte(nil), b...)
	return nil
}

// diffTextUnmarshal is a struct with UnmarshalText (not UnmarshalJSON),
// which strictjson looks into as a struct.
type diffTextUnmarshal struct {
	V string `json:"v"`
}

func (d *diffTextUnmarshal) UnmarshalText(b []byte) error {
	d.V = string(b)
	return nil
}

// diffTargets are what each document is decoded into, by both
// implementations.
var diffTargets = []func() any{
	func() any { return new(any) },
	func() any { return new(fuzzNested) },
	func() any { return new(map[string][]inner) },
	func() any { return new(map[string]any) },
	func() any { return new([]fuzzNested) },
	func() any { return new(outer) },
	func() any { return new(claims) },
	func() any { return new(**claims) },
	newOf(diffFolds),
	newOf(reflect.ArrayOf(2, diffFolds)),
	newOf(reflect.MapOf(reflect.TypeFor[string](), diffFolds)),
	func() any { return new(diffNode) },
	func() any { return new(diffEmbedded) },
	func() any { return new(json.RawMessage) },
	func() any { return new(diffCustom) },
	func() any { return new(map[string]diffCustom) },
	func() any { return new(diffTextUnmarshal) },
	func() any { return new(string) },
	func() any { return new(map[string][]string) },
	func() any { return diffNode{} }, // not a pointer
	func() any { return nil },
}

// checkDifferential decodes data into each of diffTargets with
// Unmarshal and legacyUnmarshal, and fails unless both refuse, with the
// same error, or both accept, decoding the same value. A case-only
// match is the one refusal whose text may differ: when there are
// several, which one legacyUnmarshal reported was the order of a map's
// iteration.
func checkDifferential(t *testing.T, data []byte) {
	t.Helper()
	// The scan's syntax is json.Valid's: the decode that follows it
	// would otherwise hide a difference.
	s := scanner{data: data, max: math.MaxInt}
	switch err := s.document(nil); {
	case err == nil && !json.Valid(data):
		t.Fatalf("%q: the scan accepted what json.Valid refuses", data)
	case err == errSyntax && json.Valid(data):
		t.Fatalf("%q: the scan refused as invalid what json.Valid accepts", data)
	}
	for i, target := range diffTargets {
		got, want := target(), target()
		gotErr := Unmarshal(data, got)
		wantErr := legacyUnmarshal(data, want)
		if !sameRefusal(gotErr, wantErr) {
			t.Fatalf("%q into %T (target %d): Unmarshal: %v; the separate passes: %v", data, want, i, gotErr, wantErr)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%q into %T (target %d): Unmarshal decoded %#v; the separate passes %#v", data, want, i, got, want)
		}
	}
}

func sameRefusal(got, want error) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	const caseOnly = "names are case-sensitive"
	if strings.Contains(got.Error(), caseOnly) && strings.Contains(want.Error(), caseOnly) {
		return true
	}
	return got.Error() == want.Error()
}

// TestDifferential holds Unmarshal to the separate passes it replaces,
// on adversarial documents and on 20,000 generated ones.
func TestDifferential(t *testing.T) {
	for _, doc := range adversarialDocuments() {
		checkDifferential(t, []byte(doc))
	}
	rng := rand.New(rand.NewPCG(1, 2))
	src := make([]byte, 512)
	for range 20000 {
		for i := range src {
			src[i] = byte(rng.Uint32())
		}
		g := jsonGen{src: src}
		checkDifferential(t, g.document())
	}
}

// adversarialDocuments are documents at the edges of each check.
func adversarialDocuments() []string {
	docs := []string{
		``, ` `, `{`, `}`, `[`, `]`, `{}`, `[]`, `""`, `"`, `0`, `-`, `-0`, `01`, `1.`, `1.e1`, `1e`, `1e+`, `1E-0`,
		`-1.5e+300`, `1e400`, `tru`, `true`, `truex`, `nul`, `null `, ` false`, `[1,]`, `{"a":1,}`, `{"a"}`, `{"a":}`,
		`{,}`, `[,1]`, `{"a":1 "b":2}`, `[1 2]`, `{} {}`, `{}x`, "\xef\xbb\xbf{}", "{\"a\":\"\x01\"}", "\"\x7f\"",
		`{"a":1,"a":2}`, `{"a":1,"~u0061":2}`, `{"~u0061":1,"a":2}`, `{"` + eAcute + `":1,"~u00e9":2}`, `{"~u00E9":1,"~u00e9":2}`,
		`{"` + emoji + `":1,"~ud83d~ude00":2}`, `{"~uD83D~uDE00":1,"~ud83d~ude00":2}`, `{"a\/b":1,"a/b":2}`, `{"\"":1,"~u0022":2}`,
		`{"~u0000":1,"\b":2,"~u0008":3}`, `{"a~u0000":1,"a":2}`,
		`{"x":{"a":1},"y":{"a":1}}`, `{"x":[{"a":1,"a":2}]}`, `[{"a":1},{"a":1,"b":{"c":1,"c":2}}]`,
		`{"nonce":"a","Nonce":"b"}`, `{"Nonce":"b","nonce":"a","nonce":"c"}`, `{"NONCE":1,"x":{"y":1,"y":2}}`,
		`{"kid":"k","Kid":"j"}`, `{"Kid":"j","x":[1,2,{"a":1,"a":1}]}`, `{"~u004bid":1}`, `{"k~u0069d":1}`,
		`{"K":1}`, `{"k":1}`, `{"` + kelvin + `":1}`, `{"~u212a":1}`, `{"~u212A":1,"k":1}`, `{"s":1}`, `{"S":1}`,
		`{"` + longS + `":1}`, `{"~u017f":1}`, `{"` + sharpS + `":1}`, `{"` + capSharpS + `":1}`, `{"~u1e9e":1}`,
		`{"` + dotI + `":1}`, `{"i":1}`, `{"I":1}`, `{"` + dotlessI + `":1}`, `{"a":"x","A":"y"}`, `{"` + romanXII + `":"x"}`,
		`{"~u216b":"x"}`, `{"` + emoji + `":"x"}`, `{"` + longS + `":"x","s":"y"}`, `{"` + EAcute + `":1}`,
		`{"~ud83d~ude00":1}`, `{"~ud83d~ude01":1}`, `"~ud83d~ude00"`, `"~ud83d"`, `"~ude00"`, `"~ud83d~ude00~ud83d"`, `"~ud83dx"`,
		`"~ud83d\\ude00"`, `"~ud83d~u0041"`, `"~ude00~ud83d"`, `"~ud83d~ud83d~ude00"`, `{"~udfff":1}`, `["~ud800`,
		`"~udbff~udfff"`, `"~ud800~udc00"`, `"~ud7ff~ue000"`, `"~ud83d~ude0"`, `"~ud83d~u"`, `"~ud83d\"`,
		`"~u12"`, `"~u12g4"`, `"\x"`, `"\`, `"\\"`, `"a\\ud800"`, `"~u00e9\n~u20ac\/\b\f\r\t\""`, `"~u2028~u2029"`,
		"\"\x1f\"", "\"\x00\"", "\"\x20\"", "[\x0c]", "\x0b{}", "\x0d\x0a\x09{}",
		"\"\xff\"", "\"\xed\xa0\x80\"", "{\"n\xc3\":1}", "[\"\xc3\"]", "\xff", "\"\xf4\x90\x80\x80\"", "\"\xef\xbf\xbd\"",
		`{"claims":{"NONCE":"a"}}`, `{"list":[{"nonce":"a"},{"Nonce":"b"}]}`, `{"by_name":{"x":{"Aud":"a"}}}`,
		`{"pointer":{"KID":"k"}}`, `{"raw":{"Nonce":"a","nonce":"b"}}`, `{"other":{"Nonce":"a"},"Other":{"nonce":"b"}}`,
		`{"claims":[{"Nonce":1}]}`, `{"list":{"x":{"Nonce":1}}}`, `{"by_name":[{"Nonce":1}]}`, `{"claims":null}`,
		`{"deep":{"a":[{"kid":"x","KID":"y"}]}}`, `{"deep":{"a":{"KID":"y"}}}`, `{"arr":[{"kid":1},{"kid":2},{"Kid":3}]}`,
		`{"kids":[{"kids":[{"next":{"by_id":{"x":{"NAME":"n"}}}}]}]}`, `{"next":{"next":{"next":{"Name":"n"}}}}`,
		`{"kid":"a","KID":"b"}`, `{"Kid":"a"}`, `{"m":{"a":{"b":{"KID":"x"}}}}`, `{"ptrs":[{"a":[{"KID":1}]}]}`,
		`{"text":{"a":{"V":"x"}}}`, `{"text":{"a":"plain"}}`, `{"iface":{"Kid":1,"kid":2}}`, `{"num":1e5}`,
		`{"Raw":1}`, `{"raw":{"a":[1,{"b":2,"b":3}]}}`, `[{"Kid":1},{"kid":1}]`, `[{"K":"x"}]`,
		`{"a":` + strings.Repeat(`{"a":`, 40) + `{"a":1,"a":2}` + strings.Repeat(`}`, 41),
		strings.Repeat("[", 10000) + strings.Repeat("]", 10000),
		strings.Repeat("[", 10001) + strings.Repeat("]", 10001),
		strings.Repeat(`{"a":`, 9999) + "{}" + strings.Repeat("}", 9999),
		strings.Repeat(`{"a":`, 10000) + "{}" + strings.Repeat("}", 10000),
		strings.Repeat("[", 10001) + "\xff",
		strings.Repeat("[", 5000) + `{"a":1,"a":2}` + strings.Repeat("]", 4999),
		`{"a":1,"a":2` + "\xff" + `}`, `{"a":1,"a":2,"b":"~ud800"}`, `{"Nonce":1,"b":"~ud800"}`, `{"Nonce":1,"a":1,"a":2}`,
		`{"a":"~ud800","b":` + "\"\xff\"}", `{"a":1,"a":2,"b":}`, `{"Nonce":1,}`, `{"a":"~ud800",}`,
	}
	// Objects with more members than the duplicate check compares one
	// by one, with a duplicate early, late, or not at all.
	for _, dupAt := range []int{-1, 0, linearNames - 1, linearNames, linearNames + 1, 40} {
		var b strings.Builder
		b.WriteString("{")
		for i := range 48 {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"k%d":%d`, i, i)
			if i == dupAt+1 && dupAt >= 0 {
				fmt.Fprintf(&b, `,"k%d":0`, dupAt)
			}
		}
		b.WriteString(`,"Nonce":1}`)
		docs = append(docs, b.String())
	}
	for i := range docs {
		docs[i] = u(docs[i])
	}
	return docs
}

// FuzzDifferential holds Unmarshal to the separate passes it replaces
// (legacyUnmarshal), on the fuzzer's bytes as they are and on a JSON
// document generated from them: names that fold to the target types'
// field names, escapes of them, surrogates paired and lone, nesting,
// duplicates, maps, embedded structs, json.RawMessage and any, with
// some documents then broken by a byte.
func FuzzDifferential(f *testing.F) {
	for _, doc := range adversarialDocuments() {
		if len(doc) < 1<<10 {
			f.Add([]byte(doc))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<16 {
			return
		}
		checkDifferential(t, data)
		g := jsonGen{src: data}
		checkDifferential(t, g.document())
	})
}

// jsonGen generates a JSON document, choosing by the bytes of src; once
// they run out, it finishes with one member or element per level.
type jsonGen struct {
	src []byte
	pos int
	b   bytes.Buffer
}

func (g *jsonGen) next() int {
	if g.pos >= len(g.src) {
		return 1 // no more space, members or elements than one
	}
	c := g.src[g.pos]
	g.pos++
	return int(c)
}

func (g *jsonGen) pick(n int) int { return g.next() % n }

// genNames are names the target types' fields have, and names that
// fold to them or nearly do.
var genNames = []string{
	"kid", "Kid", "KID", "nonce", "Nonce", "NONCE", "aud", "Aud", "Plain", "plain", "PLAIN", "other", "Other",
	"items", "Items", "by_key", "BY_KEY", "ptr", "Ptr", "raw", "Raw", "any", "Any", "arr", "Arr", "deep", "Deep",
	"claims", "Claims", "list", "List", "by_name", "pointer", "Pointer", "Ignored", "-",
	"name", "Name", "kids", "Kids", "next", "NEXT", "by_id", "m", "M", "iface", "num", "ptrs", "text", "v", "V",
	"a", "A", "s", "S", "k", "K", "i", "I", "x", "", kelvin, longS, sharpS, capSharpS, dotI, dotlessI, emoji,
	romanXII, romanxii, eAcute, EAcute,
}

// genStrings are a string's pieces, and genBadStrings pieces that make
// it text Unmarshal refuses, or not JSON at all.
var (
	genStrings = []string{
		`a`, `~ud83d~ude00`, `~uD83D~uDE00`, emoji, `\\`, `\"`, `\/`, `\b\f\n\r\t`, eAcute, `~u00e9`, `~u0000`,
		`~u2028`, `\\ud800`, `~u004b`, `~u212a`,
	}
	genBadStrings = []string{
		`~ud83d`, `~ude00`, `~ud83d~u0041`, `~ud83dx`, `~ude00~ud83d`, "\xff", "\xed\xa0\x80", "\x01", `\x`, `~u12`,
	}
)

func (g *jsonGen) document() []byte {
	g.b.Reset()
	g.space()
	g.value(0)
	g.space()
	doc := bytes.Clone(g.b.Bytes())
	// Sometimes break it, by a byte.
	if len(doc) > 0 && g.pick(8) == 0 {
		at := g.pick(len(doc))
		switch g.pick(4) {
		case 0:
			doc = doc[:at]
		case 1:
			doc[at] = byte(g.next())
		case 2:
			doc = append(doc[:at:at], append([]byte{"{}[],:\"\\ \xff"[g.pick(10)]}, doc[at:]...)...)
		default:
			doc = append(doc[:at:at], doc[at+1:]...)
		}
	}
	return doc
}

func (g *jsonGen) space() {
	for g.pick(4) == 0 {
		g.b.WriteByte(" \t\n\r"[g.pick(4)])
	}
}

func (g *jsonGen) value(depth int) {
	switch k := g.pick(16); {
	case depth >= 7 || k < 6:
		g.scalar()
	case k < 11:
		g.object(depth)
	default:
		g.array(depth)
	}
}

func (g *jsonGen) object(depth int) {
	g.b.WriteByte('{')
	n := g.pick(6)
	if g.pick(8) == 0 {
		n = linearNames - 2 + g.pick(8)
	}
	var names []string
	for i := range n {
		if i > 0 {
			g.b.WriteByte(',')
		}
		g.space()
		name := genNames[g.pick(len(genNames))]
		switch {
		case len(names) > 0 && g.pick(12) == 0:
			name = names[g.pick(len(names))] // a duplicate
		case g.pick(6) == 0:
			name = fmt.Sprintf("k%d", g.pick(64))
		}
		names = append(names, name)
		g.name(name)
		g.space()
		g.b.WriteByte(':')
		g.space()
		g.value(depth + 1)
		g.space()
	}
	g.b.WriteByte('}')
}

func (g *jsonGen) array(depth int) {
	g.b.WriteByte('[')
	n := g.pick(5)
	for i := range n {
		if i > 0 {
			g.b.WriteByte(',')
		}
		g.space()
		g.value(depth + 1)
		g.space()
	}
	g.b.WriteByte(']')
}

// name writes name as a JSON string, escaping some of its characters.
func (g *jsonGen) name(name string) {
	g.b.WriteByte('"')
	for _, r := range name {
		if g.pick(4) != 0 {
			switch r {
			case '"', '\\':
				g.b.WriteByte('\\')
			}
			g.b.WriteRune(r)
			continue
		}
		hex := "%04x"
		if g.pick(2) == 0 {
			hex = "%04X"
		}
		if r >= 0x10000 {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&g.b, `\u`+hex+`\u`+hex, hi, lo)
		} else {
			fmt.Fprintf(&g.b, `\u`+hex, r)
		}
	}
	g.b.WriteByte('"')
}

func (g *jsonGen) scalar() {
	switch g.pick(8) {
	case 0:
		g.b.WriteString([]string{"true", "false", "null"}[g.pick(3)])
	case 1:
		g.b.WriteString([]string{"0", "-1", "1.5", "-0.0e-1", "1E+2", "1e400", "123456789012345678901234567890"}[g.pick(7)])
	case 2:
		g.name(genNames[g.pick(len(genNames))])
	default:
		g.b.WriteByte('"')
		for range g.pick(4) {
			s := genStrings[g.pick(len(genStrings))]
			if g.pick(24) == 0 {
				s = genBadStrings[g.pick(len(genBadStrings))]
			}
			g.b.WriteString(u(s))
		}
		g.b.WriteByte('"')
	}
}
