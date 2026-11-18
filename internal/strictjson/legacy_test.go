package strictjson

// legacyUnmarshal is Unmarshal as it was before the single-pass
// scanner: json.Valid, checkText, a json.Decoder.Token walk for
// duplicates, and a decode of every object and array for case-only
// matches, each over the whole document. It's kept, unchanged but for
// its names, as the reference TestDifferential and FuzzDifferential
// hold Unmarshal to: the scanner must refuse exactly what it refuses,
// and accept exactly what it accepts.

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

func legacyUnmarshal(data []byte, v any) error {
	// json.Valid bounds the nesting depth before legacyCheckDuplicates
	// recurses, and its error is encoding/json's own.
	if !json.Valid(data) {
		return json.Unmarshal(data, v)
	}
	if err := legacyCheckText(data); err != nil {
		return err
	}
	if err := legacyCheckDuplicates(data); err != nil {
		return err
	}
	if t := reflect.TypeOf(v); t != nil && t.Kind() == reflect.Pointer {
		if err := legacyCheckCase(data, t.Elem()); err != nil {
			return err
		}
	}
	return json.Unmarshal(data, v)
}

// legacyCheckText refuses data that isn't UTF-8, or that escapes a lone
// surrogate. data is valid JSON, so a backslash is always inside a
// string and "\u" is always followed by four hex digits.
func legacyCheckText(data []byte) error {
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
		r := legacyEscapedUnit(data[i+1 : i+5])
		i += 4
		if !utf16.IsSurrogate(r) {
			continue
		}
		// A high surrogate followed by an escaped low one is a pair.
		if r < 0xdc00 && i+6 < len(data) && data[i+1] == '\\' && data[i+2] == 'u' {
			if low := legacyEscapedUnit(data[i+3 : i+7]); low >= 0xdc00 && low <= 0xdfff {
				i += 6
				continue
			}
		}
		return fmt.Errorf("json: \\u%s is a lone surrogate", data[i-3:i+1])
	}
	return nil
}

// legacyEscapedUnit is the UTF-16 code unit four hex digits name.
func legacyEscapedUnit(hex []byte) rune {
	n, _ := strconv.ParseUint(string(hex), 16, 16)
	return rune(n)
}

// legacyCheckDuplicates refuses an object with two members of one name, at
// any depth.
func legacyCheckDuplicates(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return legacyWalkValue(dec)
}

func legacyWalkValue(dec *json.Decoder) error {
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
			if err := legacyWalkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // '}'
		return err
	case json.Delim('['):
		for dec.More() {
			if err := legacyWalkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token() // ']'
		return err
	}
	return nil
}

var legacyUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// legacyCheckCase refuses, in data decoded as t, a member that matches a
// struct field's name only case-insensitively, following the members
// that name fields exactly into their types.
func legacyCheckCase(data []byte, t reflect.Type) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(legacyUnmarshalerType) {
		return nil
	}
	trimmed := bytes.TrimSpace(data)
	switch t.Kind() {
	case reflect.Struct:
		return legacyCheckStructCase(trimmed, t)
	case reflect.Slice, reflect.Array:
		return legacyCheckArrayCase(trimmed, t)
	case reflect.Map:
		return legacyCheckMapCase(trimmed, t)
	}
	return nil
}

// legacyCheckStructCase is legacyCheckCase for a struct type t.
func legacyCheckStructCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return nil // encoding/json reports the type mismatch
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	fields := legacyFieldTypes(t)
	for member, raw := range members {
		if ft, ok := fields[member]; ok {
			if err := legacyCheckCase(raw, ft); err != nil {
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

// legacyCheckArrayCase is legacyCheckCase for a slice or array type t.
func legacyCheckArrayCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("[")) {
		return nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(trimmed, &elems); err != nil {
		return err
	}
	for _, e := range elems {
		if err := legacyCheckCase(e, t.Elem()); err != nil {
			return err
		}
	}
	return nil
}

// legacyCheckMapCase is legacyCheckCase for a map type t.
func legacyCheckMapCase(trimmed []byte, t reflect.Type) error {
	if !bytes.HasPrefix(trimmed, []byte("{")) {
		return nil
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &members); err != nil {
		return err
	}
	for _, raw := range members {
		if err := legacyCheckCase(raw, t.Elem()); err != nil {
			return err
		}
	}
	return nil
}

var legacyCache sync.Map // reflect.Type → map[string]reflect.Type

// legacyFieldTypes maps the member names encoding/json maps to t's fields,
// including those of embedded structs, to the fields' types.
func legacyFieldTypes(t reflect.Type) map[string]reflect.Type {
	if names, ok := legacyCache.Load(t); ok {
		return names.(map[string]reflect.Type)
	}
	names := map[string]reflect.Type{}
	legacyAddFields(t, names)
	legacyCache.Store(t, names)
	return names
}

func legacyAddFields(t reflect.Type, names map[string]reflect.Type) {
	for i := range t.NumField() {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if ft, ok := legacyEmbeddedStruct(f, name); ok {
			legacyAddFields(ft, names)
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

// legacyEmbeddedStruct reports the struct type of f, through a pointer, when
// f is an untagged embedded struct whose fields encoding/json promotes.
func legacyEmbeddedStruct(f reflect.StructField, name string) (reflect.Type, bool) {
	if !f.Anonymous || name != "" {
		return nil, false
	}
	ft := f.Type
	if ft.Kind() == reflect.Pointer {
		ft = ft.Elem()
	}
	return ft, ft.Kind() == reflect.Struct
}
