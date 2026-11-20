package mobile

import (
	"strings"
	"testing"
)

// A configuration is refused for a key no field has, one that names a
// field only case-insensitively, an object naming a member twice at any
// depth, or anything after the object.
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
	// encoding/json keeps the last of two members with one name: a check
	// reading the first "development" would pass what's decoded as
	// development.
	for _, c := range []struct {
		in string
		v  any
	}{
		{`{"development":false,"client_id":"w","development":true}`, &config{}},
		{`{"development":true,"tls_pins":{"a.example":["AAAA"],"a.example":[]}}`, &config{}},
		{`{"development":true,"crl_distribution_points":[{"url":"https://a.example","url":"x"}]}`, &config{}},
		{`{"development":false,"issuer_roots":"x","development":true}`, &proximityReaderConfig{}},
		{`{"development":true,"issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"x","org.iso.18013.5.1.mDL":"y"}}`, &proximityReaderConfig{}},
	} {
		if err := decodeConfig(c.in, c.v); err == nil || !strings.Contains(err.Error(), "twice") {
			t.Errorf("%s: %v, want a member named twice refused", c.in, err)
		}
	}
	_, err := NewWallet(`{"development":false,"issuer_roots":"x","development":true}`, newGoKeyStore(), newGoCredentialStore(), nil)
	if code(err) != CodeInvalidInput || !strings.Contains(err.Error(), `"development" appears twice`) {
		t.Errorf("NewWallet with development twice = %v, want invalid_input naming it", err)
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

// RespondDocuments's answers are refused for an answer naming a member
// twice, whose last value encoding/json would keep.
func TestMdocAnswers_MemberTwice(t *testing.T) {
	if _, err := mdocAnswers(`[{"document":0,"credential_id":"a","elements":[["ns","x"]]}]`); err != nil {
		t.Fatalf("mdocAnswers = %v", err)
	}
	for _, bad := range []string{
		`[{"document":0,"credential_id":"a","credential_id":"b","elements":[["ns","x"]]}]`,
		`[{"document":0,"document":1,"credential_id":"a","elements":[["ns","x"]]}]`,
	} {
		if _, err := mdocAnswers(bad); code(err) != CodeInvalidInput || !strings.Contains(err.Error(), "twice") {
			t.Errorf("%s: %v, want %s naming the member", bad, err, CodeInvalidInput)
		}
	}
}
