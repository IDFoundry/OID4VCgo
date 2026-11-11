package issuer_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/issuer"
)

// A pre-authorized Token Request's authorization_details claims
// (§5.1.1, Appendix B.1) narrow the token as an authorization code's
// grant does: the minted detail carries them, in the Token Response and
// in the access token, so the Credential Request's AuthorizedClaims are
// them, not every claim. Its requested locations narrow the minted
// detail to this Credential Issuer, with or without
// authorization_servers.
func TestPreAuthorizedTokenRequest_ClaimsNarrowTheToken(t *testing.T) {
	givenName := oid4vci.ClaimsDescription{Path: []any{"given_name"}}
	asked := oid4vci.AuthorizationDetail{
		Type: oid4vci.AuthorizationDetailsTypeOpenIDCredential, CredentialConfigurationID: "IdentityCredential",
		Claims: []oid4vci.ClaimsDescription{givenName}, Locations: []string{testIssuer},
	}
	record := func(f preAuthorizedCodeFixture) issuer.PreAuthorizedCodeRecord {
		return issuer.PreAuthorizedCodeRecord{Subject: "holder-1", Scopes: []string{"identity_credential"}, ExpiresAt: f.now.Add(time.Minute)}
	}

	t.Run("RedeemPreAuthorizedCode", func(t *testing.T) {
		f := newVerifiedPreAuthorizedCodeFixture(t, nil)
		f.issue(t, "code-1", record(f))
		got, err := redeemVerified(f, "code-1", "", []oid4vci.AuthorizationDetail{asked})
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		requireNarrowedDetails(t, f, got.AuthorizationDetails, givenName)
	})
	t.Run("ExchangePreAuthorizedCode", func(t *testing.T) {
		f := newPreAuthorizedCodeFixture(t)
		f.issue(t, "code-1", record(f))
		got, err := f.iss.ExchangePreAuthorizedCode(context.Background(), issuer.ExchangePreAuthorizedCodeRequest{
			PreAuthorizedCode: "code-1", Verified: anonymousTokenRequest(), AuthorizationDetails: []oid4vci.AuthorizationDetail{asked},
		})
		if err != nil {
			t.Fatalf("exchange: %v", err)
		}
		requireNarrowedDetails(t, f, got.AuthorizationDetails, givenName)
		// The access token carries what the Token Response does.
		var inToken []oid4vci.AuthorizationDetail
		if err := json.Unmarshal(f.tokens.lastParams.Claims["authorization_details"], &inToken); err != nil {
			t.Fatalf("the token's authorization_details: %v", err)
		}
		requireNarrowedDetails(t, f, inToken, givenName)
	})
	t.Run("asked for no claims, every claim", func(t *testing.T) {
		f := newVerifiedPreAuthorizedCodeFixture(t, nil)
		f.issue(t, "code-1", record(f))
		every := asked
		every.Claims, every.Locations = nil, nil
		got, err := redeemVerified(f, "code-1", "", []oid4vci.AuthorizationDetail{every})
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if len(got.AuthorizationDetails) != 1 || got.AuthorizationDetails[0].Claims != nil || got.AuthorizationDetails[0].Locations != nil {
			t.Errorf("authorization_details = %+v, want one without claims or locations", got.AuthorizationDetails)
		}
	})
}

// requireNarrowedDetails fails the test unless details is one minted
// detail with an identifier, locations [testIssuer] and exactly want's
// claims, which the Credential Request naming its identifier is then
// authorized for.
func requireNarrowedDetails(t *testing.T, f preAuthorizedCodeFixture, details []oid4vci.AuthorizationDetail, want ...oid4vci.ClaimsDescription) {
	t.Helper()
	if len(details) != 1 || len(details[0].CredentialIdentifiers) != 1 || !reflect.DeepEqual(details[0].Locations, []string{testIssuer}) {
		t.Fatalf("authorization_details = %+v, want one with an identifier and locations [%s]", details, testIssuer)
	}
	if !reflect.DeepEqual(details[0].Claims, want) {
		t.Errorf("claims = %v, want %v", details[0].Claims, want)
	}
	claims, err := f.iss.ResolveAuthorizedClaims(
		issuer.AuthorizedRequest{ClientIdentity: issuer.KnownClientID("wallet-1"), AuthorizationDetails: details},
		issuer.CredentialRequest{CredentialIdentifier: details[0].CredentialIdentifiers[0]},
	)
	if err != nil {
		t.Fatalf("ResolveAuthorizedClaims: %v", err)
	}
	if !reflect.DeepEqual(claims, want) {
		t.Errorf("AuthorizedClaims = %v, want %v (nil would issue every claim)", claims, want)
	}
}
