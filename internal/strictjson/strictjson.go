// Package strictjson decodes JSON as encoding/json does, except that it
// refuses what parsers disagree on. encoding/json keeps the last of two
// members with one name, where other parsers keep the first, and also
// takes a member whose name matches a struct field only
// case-insensitively: {"nonce": "a", "Nonce": "b"} sets the field to
// "b", while a parser that matches names exactly, as JSON (RFC 8259
// §8.3) and JOSE (RFC 7515 §5.2) do, reads "a". For a signed or
// encrypted object, the two would then disagree on what was signed.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

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
//     isn't looked into.
//
// That includes json.RawMessage: duplicates inside one are refused
// with the rest of the document, but its member names can only be
// checked against the type it is later decoded into, so decode it
// with Unmarshal too, never with encoding/json. A custom UnmarshalJSON
// on protocol data should likewise decode with Unmarshal.
func Unmarshal(data []byte, v any) error {
	// json.Valid bounds the nesting depth before checkDuplicates
	// recurses, and its error is encoding/json's own.
	if !json.Valid(data) {
		return json.Unmarshal(data, v)
	}
	if err := checkText(data); err != nil {
		return err
	}
	if err := checkDuplicates(data); err != nil {
		return err
	}
	if t := reflect.TypeOf(v); t != nil && t.Kind() == reflect.Pointer {
		if err := checkCase(data, t.Elem()); err != nil {
			return err
		}
	}
	return json.Unmarshal(data, v)
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

// checkDuplicates refuses an object with two members of one name, at
// any depth.
func checkDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return walkValue(dec)
}

func walkValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		seen := map[string]bool{}
		for dec.More() {
			keyTok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := keyTok.(string)
			if seen[key] {
				return fmt.Errorf("json: member %q appears twice in one object", key)
			}
			seen[key] = true
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

var unmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// checkCase refuses, in data decoded as t, a member that matches a
// struct field's name only case-insensitively, following the members
// that name fields exactly into their types.
func checkCase(data []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil
	}
	trimmed := bytes.TrimSpace(data)
	switch t.Kind() {
	case reflect.Struct:
		return checkStructCase(trimmed, t)
	case reflect.Slice, reflect.Array:
		return checkArrayCase(trimmed, t)
	case reflect.Map:
		return checkMapCase(trimmed, t)
	}
	return nil
}

// checkStructCase is checkCase for a struct type t.
func checkStructCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return nil // encoding/json reports the type mismatch
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	fields := fieldTypes(t)
	for member, raw := range members {
		if ft, ok := fields[member]; ok {
			if err := checkCase(raw, ft); err != nil {
				return err
			}
			continue
		}
		for name := range fields {
			if strings.EqualFold(member, name) {
				return fmt.Errorf("json: member %q isn't %q: names are case-sensitive", member, name)
			}
		}
	}
	return nil
}

// checkArrayCase is checkCase for a slice or array type t.
func checkArrayCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("[")) {
		return nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(trimmed, &elems); err != nil {
		return err
	}
	for _, e := range elems {
		if err := checkCase(e, t.Elem()); err != nil {
			return err
		}
	}
	return nil
}

// checkMapCase is checkCase for a map type t.
func checkMapCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	for _, raw := range members {
		if err := checkCase(raw, t.Elem()); err != nil {
			return err
		}
	}
	return nil
}

var cache sync.Map // reflect.Type → map[string]reflect.Type

// fieldTypes maps the member names encoding/json maps to t's fields,
// including those of embedded structs, to the fields' types.
func fieldTypes(t reflect.Type) map[string]reflect.Type {
	if names, ok := cache.Load(t); ok {
		return names.(map[string]reflect.Type)
	}
	names := map[string]reflect.Type{}
	addFields(t, names)
	cache.Store(t, names)
	return names
}

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
