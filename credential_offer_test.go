package oid4vci_test

import (
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo"
)

func TestTxCode_Validate(t *testing.T) {
	cases := map[string]struct {
		tc      oid4vci.TxCode
		wantErr bool
	}{
		"empty is valid":         {tc: oid4vci.TxCode{}, wantErr: false},
		"numeric input_mode":     {tc: oid4vci.TxCode{InputMode: oid4vci.TxCodeInputModeNumeric}, wantErr: false},
		"text input_mode":        {tc: oid4vci.TxCode{InputMode: oid4vci.TxCodeInputModeText}, wantErr: false},
		"invalid input_mode":     {tc: oid4vci.TxCode{InputMode: "hex"}, wantErr: true},
		"negative length":        {tc: oid4vci.TxCode{Length: -1}, wantErr: true},
		"description at limit":   {tc: oid4vci.TxCode{Description: strings.Repeat("x", 300)}, wantErr: false},
		"description over limit": {tc: oid4vci.TxCode{Description: strings.Repeat("x", 301)}, wantErr: true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.tc.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestGrantPreAuthorizedCode_Validate(t *testing.T) {
	cases := map[string]struct {
		g       oid4vci.GrantPreAuthorizedCode
		wantErr bool
	}{
		"valid":        {g: oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc123"}, wantErr: false},
		"missing code": {g: oid4vci.GrantPreAuthorizedCode{}, wantErr: true},
		"invalid tx_code": {
			g:       oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc123", TxCode: &oid4vci.TxCode{Length: -1}},
			wantErr: true,
		},
		"valid tx_code": {
			g:       oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc123", TxCode: &oid4vci.TxCode{Length: 4}},
			wantErr: false,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.g.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestGrants_Validate(t *testing.T) {
	cases := map[string]struct {
		g       oid4vci.Grants
		wantErr bool
	}{
		"empty grants":         {g: oid4vci.Grants{}, wantErr: true},
		"authorization_code":   {g: oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{}}, wantErr: false},
		"valid pre-authorized": {g: oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc"}}, wantErr: false},
		"invalid pre-authorized": {
			g:       oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{}},
			wantErr: true,
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			err := c.g.Validate()
			if (err != nil) != c.wantErr {
				t.Errorf("Validate() = %v, wantErr %v", err, c.wantErr)
			}
		})
	}
}

func TestCredentialOffer_Validate(t *testing.T) {
	valid := oid4vci.CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate() = %v, want nil", err)
	}

	cases := map[string]func(*oid4vci.CredentialOffer){
		"missing credential_issuer": func(o *oid4vci.CredentialOffer) { o.CredentialIssuer = "" },
		"empty configuration ids":   func(o *oid4vci.CredentialOffer) { o.CredentialConfigurationIDs = nil },
		"duplicate configuration ids": func(o *oid4vci.CredentialOffer) {
			o.CredentialConfigurationIDs = []string{"A", "A"}
		},
		"invalid grants": func(o *oid4vci.CredentialOffer) { o.Grants = &oid4vci.Grants{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := valid
			mutate(&o)
			if err := o.Validate(); err == nil {
				t.Errorf("Validate(%s) = nil, want error", name)
			}
		})
	}
}
