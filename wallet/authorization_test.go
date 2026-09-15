package wallet_test

import (
	"testing"

	"github.com/idfoundry/fapigo/extension"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func TestBuildAuthorizationRequest_SetsScope(t *testing.T) {
	req, err := wallet.BuildAuthorizationRequest(oid4vci.CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	}, []string{"identity_credential"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}
	if len(req.Scope) != 1 || req.Scope[0] != "identity_credential" {
		t.Errorf("Scope = %v, want [identity_credential]", req.Scope)
	}
}

func TestBuildAuthorizationRequest_RejectsEmptyScopes(t *testing.T) {
	_, err := wallet.BuildAuthorizationRequest(oid4vci.CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	}, nil)
	if err == nil {
		t.Fatalf("BuildAuthorizationRequest = nil error, want error")
	}
}

func TestBuildAuthorizationRequest_AttachesIssuerState(t *testing.T) {
	offer := oid4vci.CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		Grants: &oid4vci.Grants{
			AuthorizationCode: &oid4vci.GrantAuthorizationCode{IssuerState: "opaque-state"},
		},
	}
	req, err := wallet.BuildAuthorizationRequest(offer, []string{"identity_credential"})
	if err != nil {
		t.Fatalf("BuildAuthorizationRequest: %v", err)
	}

	got, ok := extension.Get(req.Extensions, oid4vci.IssuerStateExtension)
	if !ok {
		t.Fatalf("issuer_state extension is not set")
	}
	if got != "opaque-state" {
		t.Errorf("issuer_state = %q, want %q", got, "opaque-state")
	}
}

func TestBuildAuthorizationRequest_OmitsIssuerStateWhenAbsent(t *testing.T) {
	cases := map[string]oid4vci.CredentialOffer{
		"nil grants": {
			CredentialIssuer: "https://issuer.example.com", CredentialConfigurationIDs: []string{"IdentityCredential"},
		},
		"authorization_code grant with no issuer_state": {
			CredentialIssuer: "https://issuer.example.com", CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &oid4vci.Grants{AuthorizationCode: &oid4vci.GrantAuthorizationCode{}},
		},
		"pre-authorized_code grant only": {
			CredentialIssuer: "https://issuer.example.com", CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &oid4vci.Grants{PreAuthorizedCode: &oid4vci.GrantPreAuthorizedCode{PreAuthorizedCode: "abc"}},
		},
	}
	for name, offer := range cases {
		t.Run(name, func(t *testing.T) {
			req, err := wallet.BuildAuthorizationRequest(offer, []string{"identity_credential"})
			if err != nil {
				t.Fatalf("BuildAuthorizationRequest: %v", err)
			}
			if _, ok := extension.Get(req.Extensions, oid4vci.IssuerStateExtension); ok {
				t.Errorf("issuer_state extension is set, want absent")
			}
		})
	}
}
