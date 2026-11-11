package mobile

import "testing"

// A configuration is refused for a key no field has, one that names a
// field only case-insensitively, or anything after the object.
func TestDecodeConfig(t *testing.T) {
	for in, ok := range map[string]bool{
		`{"development":true,"client_id":"w"}`: true,
		`{"require_trusted_mdoc_readr":true}`:  false,
		`{"DEVELOPMENT":true}`:                 false,
		`{"development":true} {"x":1}`:         false,
		`{"development":true} trailing`:        false,
		`[]`:                                   false,
	} {
		var cfg config
		if err := decodeConfig(in, &cfg); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
	var reader proximityReaderConfig
	if err := decodeConfig(`{"require_mdl_signer_ekus":true}`, &reader); err == nil {
		t.Error("a misspelled reader option was accepted")
	}
}

// Respond's elements are [namespace, identifier] pairs: an element of
// another length, or text after the array, is refused, not dropped or
// zero-filled.
func TestMdocElementsJSON(t *testing.T) {
	got, err := mdocElementsJSON(`[["ns","a"], ["ns","b"]] `)
	if err != nil || len(got) != 2 || got[1] != [2]string{"ns", "b"} {
		t.Fatalf("mdocElementsJSON = %v, %v", got, err)
	}
	for _, bad := range []string{`[["ns","a","extra"]]`, `[["ns"]]`, `[[]]`, `[["ns","a"]] ]`, `[["ns","a"]] [`, `{}`, `[["ns",1]]`} {
		if _, err := mdocElementsJSON(bad); code(err) != CodeInvalidInput {
			t.Errorf("%s: %v, want %s", bad, err, CodeInvalidInput)
		}
	}
}
