// Package strictjson decodes JSON as encoding/json does, except that it
// refuses what parsers disagree on. encoding/json keeps the last of two
// members with one name, where other parsers keep the first, and also
// takes a member whose name matches a struct field only
// case-insensitively: {"nonce": "a", "Nonce": "b"} sets the field to
// "b", while a parser that matches names exactly, as JSON (RFC 8259
// §8.3) and JOSE (RFC 7515 §5.2) do, reads "a". For a signed or
// encrypted object, the two would then disagree on what was signed.
//
// It checks a document in one pass over its bytes, before
// encoding/json decodes it, and bounds the document's tokens
// (DefaultMaxTokens): the size limits on what it's given bound bytes,
// and a document of small tokens costs more to decode than one long
// string of the same size.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"math/bits"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// DefaultMaxTokens is how many tokens Unmarshal accepts in one
// document: its values (objects, arrays, strings, numbers, true, false
// and null, at any depth) and its members' names. The largest honest
// documents measured hold about a tenth of it: about 9,400 in an
// issuer's metadata of 100 KB (the EUDI PID Issuer's), and 10,700 in
// Google's Android attestation status list of 180 KB.
const DefaultMaxTokens = 1 << 17

// ErrTooManyTokens is the refusal of a document with more tokens than
// Unmarshal, or UnmarshalLimit's caller, accepts.
var ErrTooManyTokens = errors.New("json: too many tokens")

// Unmarshal decodes data into v, refusing:
//   - text that isn't UTF-8 (RFC 8259 §8.1), or a \u escape of a
//     surrogate that isn't half of a pair (RFC 8259 §8.2; I-JSON, RFC
//     7493 §2.1, MUST NOT): encoding/json reads either as U+FFFD, so
//     two different documents would decode the same;
//   - an object, at any depth, with two members of one name (RFC 8259
//     §4: names "SHOULD be unique"; I-JSON, RFC 7493 §2.3, MUST);
//   - a member whose name matches one of a struct's fields only
//     case-insensitively, in v and in every struct reached through its
//     fields, slices, arrays and maps. A type with its own UnmarshalJSON
//     isn't looked into;
//   - a document of more than DefaultMaxTokens tokens
//     (ErrTooManyTokens), as soon as the scan reaches the first token
//     over it.
//
// That includes json.RawMessage: duplicates inside one are refused
// with the rest of the document, but its member names can only be
// checked against the type it is later decoded into, so decode it
// with Unmarshal too, never with encoding/json. A custom UnmarshalJSON
// on protocol data should likewise decode with Unmarshal.
func Unmarshal(data []byte, v any) error {
	return UnmarshalLimit(data, v, DefaultMaxTokens)
}

// UnmarshalLimit is Unmarshal, accepting at most maxTokens tokens
// instead of DefaultMaxTokens: more for a document whose size is
// bounded otherwise, such as by a count of entries; math.MaxInt for
// one this process wrote itself. maxTokens must be positive.
func UnmarshalLimit(data []byte, v any, maxTokens int) error {
	if maxTokens <= 0 {
		return fmt.Errorf("strictjson: a bound of %d tokens: it must be positive", maxTokens)
	}
	var sh *shape
	if t := reflect.TypeOf(v); t != nil && t.Kind() == reflect.Pointer {
		sh = shapeOf(t.Elem())
	}
	s := scanner{data: data, max: maxTokens}
	err := s.document(sh)
	switch {
	case errors.Is(err, ErrTooManyTokens):
		return err
	case err != nil:
		// The scan stops at the first refusal in the text. Report what
		// a check of the whole text in turn would: invalid JSON first,
		// with encoding/json's own error, then text that isn't UTF-8
		// anywhere, then the first lone surrogate, then the first
		// duplicate.
		if !json.Valid(data) {
			return json.Unmarshal(data, v)
		}
		if textErr := checkText(data); textErr != nil {
			return textErr
		}
		return err
	case s.caseErr != nil:
		return s.caseErr
	}
	return json.Unmarshal(data, v)
}

// maxDepth is encoding/json's bound on nesting: json.Valid refuses an
// array or object nested deeper.
const maxDepth = 10000

var (
	// errSyntax is invalid JSON: Unmarshal reports encoding/json's own
	// error for it.
	errSyntax = errors.New("json: syntax error")
	// errText is text that isn't UTF-8, or a \u escape of a lone
	// surrogate: Unmarshal reports checkText's error for it.
	errText = errors.New("json: text is not valid UTF-8, or escapes a lone surrogate")
)

// scanner checks one document: its syntax as json.Valid does, its
// text, its members' names for duplicates and, against the shape of
// the type it's decoded into, for case-only matches, and its tokens
// against max. It stops at the first refusal, except a case-only match,
// which it records in caseErr and keeps scanning: a duplicate anywhere
// is reported before it.
type scanner struct {
	data    []byte
	i       int // the next byte
	tokens  int
	max     int
	depth   int
	names   []nameRef // the names of the members of the objects being scanned, outermost first
	arena   []byte    // the unescaped text of those of them with escapes
	caseErr error
	fold    []byte // scratch for foldKey
}

// document scans data as one JSON text: a value with optional
// whitespace around it.
func (s *scanner) document(sh *shape) error {
	if err := s.value(sh); err != nil {
		return err
	}
	s.skipSpace()
	if s.i != len(s.data) {
		return errSyntax
	}
	return nil
}

// count counts one token.
func (s *scanner) count() error {
	s.tokens++
	if s.tokens > s.max {
		return fmt.Errorf("%w: more than %d values and member names", ErrTooManyTokens, s.max)
	}
	return nil
}

func (s *scanner) skipSpace() {
	for s.i < len(s.data) {
		switch s.data[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// value scans one value, whose type has shape sh (nil: none whose
// member names are checked).
func (s *scanner) value(sh *shape) error {
	s.skipSpace()
	if s.i >= len(s.data) {
		return errSyntax
	}
	if err := s.count(); err != nil {
		return err
	}
	switch c := s.data[s.i]; {
	case c == '{':
		return s.object(sh)
	case c == '[':
		return s.array(sh)
	case c == '"':
		_, _, _, err := s.scanString()
		return err
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || '0' <= c && c <= '9':
		return s.number()
	}
	return errSyntax
}

// object scans an object, at its '{'.
func (s *scanner) object(sh *shape) error {
	s.i++
	if s.depth++; s.depth > maxDepth {
		return errSyntax
	}
	s.skipSpace()
	if s.i < len(s.data) && s.data[s.i] == '}' {
		s.i++
		s.depth--
		return nil
	}
	var elem *shape // every member's, in a map
	if sh != nil && sh.kind == kindMap {
		elem = shapeOf(sh.elem)
	} else if sh != nil && sh.kind != kindStruct {
		sh = nil // an object where the type takes an array
	}
	base, arenaBase := len(s.names), len(s.arena)
	var set nameSet
	for {
		s.skipSpace()
		if s.i >= len(s.data) || s.data[s.i] != '"' {
			return errSyntax
		}
		if err := s.count(); err != nil {
			return err
		}
		ref, err := s.scanName()
		if err != nil {
			return err
		}
		if err := s.addName(base, &set, ref); err != nil {
			return err
		}
		s.skipSpace()
		if s.i >= len(s.data) || s.data[s.i] != ':' {
			return errSyntax
		}
		s.i++
		member := elem
		switch {
		case s.caseErr != nil:
			member = nil // the first is reported
		case sh != nil && sh.kind == kindStruct:
			member = s.fieldShape(sh, s.nameOf(ref))
		}
		if err := s.value(member); err != nil {
			return err
		}
		s.skipSpace()
		if s.i >= len(s.data) {
			return errSyntax
		}
		switch s.data[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			s.names, s.arena = s.names[:base], s.arena[:arenaBase]
			s.depth--
			return nil
		default:
			return errSyntax
		}
	}
}

// linearNames is how many names an object's duplicate check compares
// one by one before it builds a set of them.
const linearNames = 16

// nameSeed seeds the hash of an object's names: unknown to a sender,
// so it can't choose names that collide.
var nameSeed = maphash.MakeSeed()

// nameRef is where an object member's name is: s.data[from:to], or,
// for a name with escapes, unescaped in s.arena[-from-1:to]. Offsets,
// not slices, so the garbage collector has no pointers to follow in
// them.
type nameRef struct{ from, to int }

// nameOf is the name r refers to.
func (s *scanner) nameOf(r nameRef) []byte {
	if r.from < 0 {
		return s.arena[-r.from-1 : r.to]
	}
	return s.data[r.from:r.to]
}

// scanName scans a member's name, at its opening quote, unescaping it
// into s.arena if it holds an escape.
func (s *scanner) scanName() (nameRef, error) {
	start, end, escaped, err := s.scanString()
	if err != nil || !escaped {
		return nameRef{start, end}, err
	}
	from := len(s.arena)
	s.arena = appendUnquoted(s.arena, s.data[start:end])
	return nameRef{-from - 1, len(s.arena)}, nil
}

// nameSet is the set of the names of one object, s.names[base:], once
// it has linearNames of them: an open-addressed table of their indices
// in s.names, plus one; zero is an empty slot. The names an object
// holds stay in s.names while it's scanned: those of the objects in
// its members' values follow them only until those objects end.
type nameSet []int

// addName adds the name ref refers to to the names of the object whose
// names start at base in s.names, refusing it if it's there already.
func (s *scanner) addName(base int, set *nameSet, ref nameRef) error {
	name := s.nameOf(ref)
	if *set == nil {
		for _, n := range s.names[base:] {
			if bytes.Equal(s.nameOf(n), name) {
				return duplicate(name)
			}
		}
	} else if !s.insert(*set, len(s.names), name) {
		return duplicate(name)
	}
	s.names = append(s.names, ref)
	if n := len(s.names) - base; n >= linearNames && 2*n > len(*set) {
		// Grow the table to four times the names, with them all in it.
		*set = make(nameSet, 1<<bits.Len(uint(4*n-1)))
		for i := base; i < len(s.names); i++ {
			s.insert(*set, i, s.nameOf(s.names[i]))
		}
	}
	return nil
}

// insert adds s.names[i], name, to set, reporting false if a name
// equal to it is there already.
func (s *scanner) insert(set nameSet, i int, name []byte) bool {
	mask := uint64(len(set) - 1) //nolint:gosec // G115: len(set) is a power of two, at least 64
	for slot := maphash.Bytes(nameSeed, name) & mask; ; slot = (slot + 1) & mask {
		switch j := set[slot]; {
		case j == 0:
			set[slot] = i + 1
			return true
		case bytes.Equal(s.nameOf(s.names[j-1]), name):
			return false
		}
	}
}

func duplicate(name []byte) error {
	return fmt.Errorf("json: member %q appears twice in one object", name)
}

// fieldShape is the shape of the field of struct shape sh that the
// member named name decodes into, recording in s.caseErr a name that
// matches a field only case-insensitively.
func (s *scanner) fieldShape(sh *shape, name []byte) *shape {
	if ft, ok := sh.fields[string(name)]; ok {
		return shapeOf(ft)
	}
	s.fold = foldKey(s.fold[:0], name)
	if field, ok := sh.folded[string(s.fold)]; ok {
		s.caseErr = fmt.Errorf("json: member %q isn't %q: names are case-sensitive", name, field)
	}
	return nil
}

// array scans an array, at its '['.
func (s *scanner) array(sh *shape) error {
	s.i++
	if s.depth++; s.depth > maxDepth {
		return errSyntax
	}
	s.skipSpace()
	if s.i < len(s.data) && s.data[s.i] == ']' {
		s.i++
		s.depth--
		return nil
	}
	var elem *shape
	if sh != nil && sh.kind == kindSeq {
		elem = shapeOf(sh.elem)
	}
	for {
		if s.caseErr != nil {
			elem = nil
		}
		if err := s.value(elem); err != nil {
			return err
		}
		s.skipSpace()
		if s.i >= len(s.data) {
			return errSyntax
		}
		switch s.data[s.i] {
		case ',':
			s.i++
		case ']':
			s.i++
			s.depth--
			return nil
		default:
			return errSyntax
		}
	}
}

// scanString scans a string, at its opening quote, returning where its
// contents start and end in s.data, and whether they hold an escape.
func (s *scanner) scanString() (start, end int, escaped bool, err error) {
	data := s.data
	start = s.i + 1
	for i := start; i < len(data); {
		c := data[i]
		switch {
		case c == '"':
			s.i = i + 1
			return start, i, escaped, nil
		case c == '\\':
			escaped = true
			n, err := escapeLen(data, i)
			if err != nil {
				return 0, 0, false, err
			}
			i += n
		case c < 0x20:
			return 0, 0, false, errSyntax
		case c < utf8.RuneSelf:
			i++
		default:
			r, size := utf8.DecodeRune(data[i:])
			if r == utf8.RuneError && size == 1 {
				return 0, 0, false, errText
			}
			i += size
		}
	}
	return 0, 0, false, errSyntax
}

// escapeLen is the length of the escape at data[i], a backslash: a
// surrogate pair's two \u escapes are one. A \u escape of a lone
// surrogate is errText.
func escapeLen(data []byte, i int) (int, error) {
	if i+1 >= len(data) {
		return 0, errSyntax
	}
	switch data[i+1] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		return 2, nil
	case 'u':
	default:
		return 0, errSyntax
	}
	r, ok := hex4(data, i+2)
	if !ok {
		return 0, errSyntax
	}
	if !utf16.IsSurrogate(r) {
		return 6, nil
	}
	// A high surrogate followed by an escaped low one is a pair.
	if r < 0xdc00 && i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
		if low, ok := hex4(data, i+8); ok && low >= 0xdc00 && low <= 0xdfff {
			return 12, nil
		}
	}
	return 0, errText
}

// hex4 is the UTF-16 code unit the four hex digits at data[i] name.
func hex4(data []byte, i int) (rune, bool) {
	if i+4 > len(data) {
		return 0, false
	}
	var r rune
	for _, c := range data[i : i+4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c -= 'a' - 10
		case 'A' <= c && c <= 'F':
			c -= 'A' - 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}

// appendUnquoted appends to out raw unescaped, as encoding/json reads
// it: raw is a string's contents that scanString scanned, so its
// escapes are valid, and every surrogate escaped is half of a pair.
func appendUnquoted(out, raw []byte) []byte {
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			out = append(out, raw[i])
			i++
			continue
		}
		switch c := raw[i+1]; c {
		case 'b':
			out = append(out, '\b')
		case 'f':
			out = append(out, '\f')
		case 'n':
			out = append(out, '\n')
		case 'r':
			out = append(out, '\r')
		case 't':
			out = append(out, '\t')
		case 'u':
			r, _ := hex4(raw, i+2)
			i += 6
			if utf16.IsSurrogate(r) {
				low, _ := hex4(raw, i+2)
				r = utf16.DecodeRune(r, low)
				i += 6
			}
			out = utf8.AppendRune(out, r)
			continue
		default: // '"', '\\', '/'
			out = append(out, c)
		}
		i += 2
	}
	return out
}

// literal scans true, false or null.
func (s *scanner) literal(lit string) error {
	if len(s.data)-s.i < len(lit) || string(s.data[s.i:s.i+len(lit)]) != lit {
		return errSyntax
	}
	s.i += len(lit)
	return nil
}

// number scans a number: -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?
func (s *scanner) number() error {
	d, i := s.data, s.i
	if d[i] == '-' {
		i++
	}
	switch {
	case i < len(d) && d[i] == '0':
		i++
	case i < len(d) && '1' <= d[i] && d[i] <= '9':
		i = digits(d, i+1)
	default:
		return errSyntax
	}
	if i < len(d) && d[i] == '.' {
		i++
		if i >= len(d) || !isDigit(d[i]) {
			return errSyntax
		}
		i = digits(d, i)
	}
	if i < len(d) && (d[i] == 'e' || d[i] == 'E') {
		i++
		if i < len(d) && (d[i] == '+' || d[i] == '-') {
			i++
		}
		if i >= len(d) || !isDigit(d[i]) {
			return errSyntax
		}
		i = digits(d, i)
	}
	s.i = i
	return nil
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// digits is the index past the digits at d[i].
func digits(d []byte, i int) int {
	for i < len(d) && isDigit(d[i]) {
		i++
	}
	return i
}

// checkText refuses data that isn't UTF-8, or that escapes a lone
// surrogate. data is valid JSON, so a backslash is always inside a
// string and "\u" is always followed by four hex digits.
func checkText(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("json: text is not valid UTF-8")
	}
	for i := 0; i < len(data); i++ {
		if data[i] != '\\' {
			continue
		}
		i++ // the escaped character
		if data[i] != 'u' {
			continue
		}
		r := escapedUnit(data[i+1 : i+5])
		i += 4
		if !utf16.IsSurrogate(r) {
			continue
		}
		// A high surrogate followed by an escaped low one is a pair.
		if r < 0xdc00 && i+6 < len(data) && data[i+1] == '\\' && data[i+2] == 'u' {
			if low := escapedUnit(data[i+3 : i+7]); low >= 0xdc00 && low <= 0xdfff {
				i += 6
				continue
			}
		}
		return fmt.Errorf("json: \\u%s is a lone surrogate", data[i-3:i+1])
	}
	return nil
}

// escapedUnit is the UTF-16 code unit four hex digits name.
func escapedUnit(hex []byte) rune {
	n, _ := strconv.ParseUint(string(hex), 16, 16)
	return rune(n)
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

type shapeKind uint8

const (
	kindStruct shapeKind = iota + 1 // members are checked against fields
	kindSeq                         // a slice or array: elements have elem's shape
	kindMap                         // members' values have elem's shape
)

// shape is what Unmarshal checks of a value decoded into a type: a
// struct's member names, and the shapes of the values it decodes into
// further types. A nil *shape checks nothing: a type with its own
// UnmarshalJSON, an interface, or a scalar.
type shape struct {
	kind   shapeKind
	fields map[string]reflect.Type // a struct's: member name → field type
	folded map[string]string       // a struct's: foldKey of a member name → the name
	elem   reflect.Type            // a slice's, array's or map's
}

var shapes sync.Map // reflect.Type → *shape

// shapeOf is t's shape. It's computed once per type, and the shapes of
// the types t holds only when a value reaches them, so a recursive type
// has one.
func shapeOf(t reflect.Type) *shape {
	if sh, ok := shapes.Load(t); ok {
		return sh.(*shape)
	}
	sh := newShape(t)
	shapes.Store(t, sh)
	return sh
}

func newShape(t reflect.Type) *shape {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		fields := map[string]reflect.Type{}
		addFields(t, fields)
		folded := make(map[string]string, len(fields))
		for name := range fields {
			folded[string(foldKey(nil, []byte(name)))] = name
		}
		return &shape{kind: kindStruct, fields: fields, folded: folded}
	case reflect.Slice, reflect.Array:
		return &shape{kind: kindSeq, elem: t.Elem()}
	case reflect.Map:
		return &shape{kind: kindMap, elem: t.Elem()}
	}
	return nil
}

// foldKey appends to dst name with each character replaced by the
// least of the characters Unicode's simple case folding makes it equal
// to, so that two names have one key exactly when strings.EqualFold
// reports them equal. name is UTF-8.
func foldKey(dst, name []byte) []byte {
	for i := 0; i < len(name); {
		c := name[i]
		if c < utf8.RuneSelf {
			if 'a' <= c && c <= 'z' {
				c -= 'a' - 'A'
			}
			dst = append(dst, c)
			i++
			continue
		}
		r, size := utf8.DecodeRune(name[i:])
		i += size
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		dst = utf8.AppendRune(dst, least)
	}
	return dst
}

// addFields maps the member names encoding/json maps to t's fields,
// including those of embedded structs, to the fields' types.
func addFields(t reflect.Type, names map[string]reflect.Type) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if ft, ok := embeddedStruct(f, name); ok {
			addFields(ft, names)
			continue
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		names[name] = f.Type
	}
}

// embeddedStruct reports the struct type of f, through a pointer, when
// f is an untagged embedded struct whose fields encoding/json promotes.
func embeddedStruct(f reflect.StructField, name string) (reflect.Type, bool) {
	if !f.Anonymous || name != "" {
		return nil, false
	}
	ft := f.Type
	if ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	return ft, ft.Kind() == reflect.Struct
}
