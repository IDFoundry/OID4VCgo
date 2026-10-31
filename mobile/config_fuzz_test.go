package mobile

import (
	"crypto/ecdsa"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// configKeys is the JSON object keys a configuration struct of type t
// takes: its fields' exact json names.
func configKeys(t reflect.Type) map[string]bool {
	keys := map[string]bool{}
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			keys[name] = true
		}
	}
	return keys
}

// checkConfigOutcome fails t when a configuration call's outcome breaks
// the boundary's rules: an error is an *Error, so the app gets a code;
// and an accepted configuration is one object whose every key is one
// of keys exactly, with nothing after it.
func checkConfigOutcome(t *testing.T, what, configJSON string, keys map[string]bool, err error) {
	t.Helper()
	if err != nil {
		if code(err) == "" {
			t.Fatalf("%s(%q): an error without a code: %v", what, configJSON, err)
		}
		return
	}
	dec := json.NewDecoder(strings.NewReader(configJSON))
	var members map[string]json.RawMessage
	if err := dec.Decode(&members); err != nil || dec.More() {
		t.Fatalf("%s accepted %q, which isn't one JSON object", what, configJSON)
	}
	for k := range members {
		if !keys[k] {
			t.Fatalf("%s accepted %q, with the key %q", what, configJSON, k)
		}
	}
}

// FuzzNewWalletConfig: NewWallet's configuration JSON, from the app,
// never panics; it's refused with a coded error, or it's one object
// naming only configuration keys, exactly.
func FuzzNewWalletConfig(f *testing.F) {
	for _, seed := range []string{
		`{"development":true}`,
		`{"development":true,"DEVELOPMENT":false}`,
		`{"development":true,"development":false}`,
		`{"development":true} {}`,
		`{"development":false,"issuer_roots":"x","revocation":["issuer"],"tls_pins":{"*.a":["AAAA"]}}`,
		`{"development":true,"mdoc_issuer_roots_by_doctype":{"a":""},"copy_policy":"per_verifier","proximity_device_auth":"mac_preferred"}`,
		`{"development":true,"batch_size":-1,"locales":["fr",""],"max_issuer_metadata_age_seconds":1e99}`,
		`{"development":true,"status_issuers":{"x":"y"},"crls":"-----BEGIN X509 CRL-----\n"}`,
	} {
		f.Add(seed)
	}
	keys := configKeys(reflect.TypeFor[config]())
	f.Fuzz(func(t *testing.T, configJSON string) {
		_, err := NewWallet(configJSON, &goKeyStore{keys: map[string]*ecdsa.PrivateKey{}}, memStore{records: map[string][]byte{}}, nil)
		checkConfigOutcome(t, "NewWallet", configJSON, keys, err)
	})
}

// FuzzNewProximityReaderConfig: NewProximityReader's configuration JSON
// never panics; it's refused with a coded error, or it's one object
// naming only configuration keys, exactly.
func FuzzNewProximityReaderConfig(f *testing.F) {
	for _, seed := range []string{
		`{"development":true}`,
		`{"development":true,"Development":true}`,
		`{"development":true,"max_clock_skew_seconds":-9223372036854775808}`,
		`{"development":false,"issuer_roots":"x","any_issuer_for_any_type":true,"revocation":["issuer","reader"]}`,
		`{"development":true,"issuer_roots_by_doctype":{"org.iso.18013.5.1.mDL":"x"},"reader_key_id":"k"}`,
		`{"development":true,"reader_key_id":"k","reader_chain":"-----BEGIN CERTIFICATE-----\n"}`,
		`{"development":true,"require_mdl_signer_eku":true,"accept_mdl_signer_without_eku":true}`,
	} {
		f.Add(seed)
	}
	keys := configKeys(reflect.TypeFor[proximityReaderConfig]())
	f.Fuzz(func(t *testing.T, configJSON string) {
		_, err := NewProximityReader(configJSON, newGoKeyStore())
		checkConfigOutcome(t, "NewProximityReader", configJSON, keys, err)
	})
}
