package storetest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"time"
)

var (
	timeType = reflect.TypeFor[time.Time]()
	rawType  = reflect.TypeFor[json.RawMessage]()
)

// diff describes where got differs from want, field by field: times
// compared with Equal, JSON compared as values, a nil slice or map equal
// to an empty one, and a struct with no exported fields (fapi.Secret)
// compared whole.
func diff[T any](got, want T) []string {
	var out []string
	diffValues("", reflect.ValueOf(&got).Elem(), reflect.ValueOf(&want).Elem(), &out)
	return out
}

func diffValues(path string, got, want reflect.Value, out *[]string) {
	mismatch := func(format string, args ...any) {
		*out = append(*out, fmt.Sprintf("%s: "+format, append([]any{fieldPath(path)}, args...)...))
	}
	if !got.IsValid() || !want.IsValid() {
		if got.IsValid() != want.IsValid() {
			mismatch("got %v, want %v", got, want)
		}
		return
	}
	if got.Type() != want.Type() {
		mismatch("got a %v, want a %v", got.Type(), want.Type())
		return
	}
	switch got.Type() {
	case timeType:
		if g, w := got.Interface().(time.Time), want.Interface().(time.Time); !g.Equal(w) {
			mismatch("got %v, want %v", g, w)
		}
		return
	case rawType:
		if !jsonEqual(got.Bytes(), want.Bytes()) {
			mismatch("got %s, want %s", got.Bytes(), want.Bytes())
		}
		return
	}
	switch got.Kind() {
	case reflect.Pointer, reflect.Interface:
		if got.IsNil() || want.IsNil() {
			if got.IsNil() != want.IsNil() {
				mismatch("got %#v, want %#v", got.Interface(), want.Interface())
			}
			return
		}
		diffValues(path, got.Elem(), want.Elem(), out)
	case reflect.Struct:
		exported := false
		for i := range got.NumField() {
			if f := got.Type().Field(i); f.IsExported() {
				exported = true
				diffValues(path+"."+f.Name, got.Field(i), want.Field(i), out)
			}
		}
		if !exported && !reflect.DeepEqual(got.Interface(), want.Interface()) {
			mismatch("differs")
		}
	case reflect.Slice:
		if got.Len() != want.Len() {
			mismatch("got %d elements, want %d", got.Len(), want.Len())
			return
		}
		for i := range got.Len() {
			diffValues(fmt.Sprintf("%s[%d]", path, i), got.Index(i), want.Index(i), out)
		}
	case reflect.Map:
		if got.Len() != want.Len() {
			mismatch("got %d entries, want %d", got.Len(), want.Len())
			return
		}
		for _, k := range want.MapKeys() {
			g := got.MapIndex(k)
			if !g.IsValid() {
				mismatch("missing key %v", k)
				continue
			}
			diffValues(fmt.Sprintf("%s[%v]", path, k), g, want.MapIndex(k), out)
		}
	default:
		if !reflect.DeepEqual(got.Interface(), want.Interface()) {
			mismatch("got %#v, want %#v", got.Interface(), want.Interface())
		}
	}
}

// jsonEqual reports whether a and b are the same JSON value, or both
// empty.
func jsonEqual(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil {
		return bytes.Equal(a, b)
	}
	return reflect.DeepEqual(va, vb)
}

// unset lists v's fields left at their zero value, nil or empty,
// through every nested struct, pointer and slice element: a fixture
// meant to set them all names what it misses — a field added to a
// record type later included.
func unset(v any) []string {
	var out []string
	unsetValues("", reflect.ValueOf(v), &out)
	return out
}

func unsetValues(path string, v reflect.Value, out *[]string) {
	if v.Type() == timeType {
		if v.IsZero() {
			*out = append(*out, fieldPath(path))
		}
		return
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			*out = append(*out, fieldPath(path))
			return
		}
		unsetValues(path, v.Elem(), out)
	case reflect.Struct:
		exported := false
		for i := range v.NumField() {
			if f := v.Type().Field(i); f.IsExported() {
				exported = true
				unsetValues(path+"."+f.Name, v.Field(i), out)
			}
		}
		if !exported && v.IsZero() {
			*out = append(*out, fieldPath(path))
		}
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			*out = append(*out, fieldPath(path))
			return
		}
		if v.Kind() == reflect.Slice && v.Type().Elem().Kind() != reflect.Uint8 {
			for i := range v.Len() {
				unsetValues(fmt.Sprintf("%s[%d]", path, i), v.Index(i), out)
			}
		}
	default:
		if v.IsZero() {
			*out = append(*out, fieldPath(path))
		}
	}
}

func fieldPath(path string) string {
	if path == "" {
		return "the record"
	}
	return path[1:]
}
