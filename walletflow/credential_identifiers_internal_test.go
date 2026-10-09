package walletflow

import (
	"reflect"
	"testing"

	oid4vci "github.com/idfoundry/oid4vcgo"
)

// A Token Response's credential_identifiers are kept per configuration,
// from openid_credential details only.
func TestCredentialIdentifiers(t *testing.T) {
	got, err := credentialIdentifiers([]byte(`[
		{"type":"openid_credential","credential_configuration_id":"pid","credential_identifiers":["pid-1","pid-2"],"extra":true},
		{"type":"openid_credential","credential_configuration_id":"mdl"},
		{"type":"payment_initiation","credential_configuration_id":"pid","credential_identifiers":["other"]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"pid": {"pid-1", "pid-2"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("credentialIdentifiers = %v, want %v", got, want)
	}

	if got, err := credentialIdentifiers(nil); got != nil || err != nil {
		t.Errorf("without authorization_details: %v, %v; want none", got, err)
	}
	if _, err := credentialIdentifiers([]byte(`{"type":"openid_credential"}`)); err == nil {
		t.Error("authorization_details that isn't an array accepted")
	}
}

// An offer is unbound, and so refused a Bearer access token, if any
// credential it offers is bound to no key.
func TestIssuanceUnbound(t *testing.T) {
	bound := oid4vci.CredentialConfigurationMetadata{CryptographicBindingMethodsSupported: []string{"jwk"}}
	metadata := oid4vci.Metadata{CredentialConfigurationsSupported: map[string]oid4vci.CredentialConfigurationMetadata{
		"bound": bound, "unbound": {},
	}}
	for ids, want := range map[[2]string]bool{{"bound", "bound"}: false, {"bound", "unbound"}: true, {"unbound", "unbound"}: true} {
		s := &Issuance{metadata: metadata, offer: oid4vci.CredentialOffer{CredentialConfigurationIDs: ids[:]}}
		if got := s.unbound(); got != want {
			t.Errorf("unbound(%v) = %v, want %v", ids, got, want)
		}
	}
}
