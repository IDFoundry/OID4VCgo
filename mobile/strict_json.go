package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/idfoundry/oid4vcgo/internal/strictjson"
)

// decodeConfig decodes configJSON, one JSON object, into v, a pointer to
// a configuration struct, refusing what would otherwise pass silently: a
// key no field has (a misspelled require_* option stays at its default),
// one that names a field only case-insensitively ("DEVELOPMENT" would
// set development, past a check for the exact key), an object, at any
// depth, naming a member twice (encoding/json keeps the last, so a
// second "development" would set it past a check that reads the
// first), and anything after the object.
func decodeConfig(configJSON string, v any) error {
	var keys map[string]json.RawMessage
	if err := strictjson.Unmarshal([]byte(configJSON), &keys); err != nil {
		return err
	}
	fields := map[string]bool{}
	t := reflect.TypeOf(v).Elem()
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			fields[name] = true
		}
	}
	for k := range keys {
		if !fields[k] {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	dec := json.NewDecoder(strings.NewReader(configJSON))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the configuration object")
	}
	return nil
}

// decodeStrict decodes text, one JSON value, into v, refusing an object
// member no field has, an object naming a member twice, and anything
// after the value.
func decodeStrict(text string, v any) error {
	if err := strictjson.Unmarshal([]byte(text), new(json.RawMessage)); err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("unexpected data after the value")
	}
	return nil
}
