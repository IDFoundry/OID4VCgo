package issuer_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/issuer"
)

func newTestIssuer(t *testing.T, cfg issuer.Config, deps issuer.Dependencies) *issuer.Issuer {
	t.Helper()
	iss, err := issuer.New(cfg, deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return iss
}

func decodeOfferURI(t *testing.T, uri, param string) issuer.CredentialOffer {
	t.Helper()
	if !strings.HasPrefix(uri, "openid-credential-offer://?") {
		t.Fatalf("URI = %q, want openid-credential-offer:// scheme", uri)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", uri, err)
	}
	raw := parsed.Query().Get(param)
	if raw == "" {
		t.Fatalf("URI %q has no %q query parameter", uri, param)
	}
	var offer issuer.CredentialOffer
	if err := json.Unmarshal([]byte(raw), &offer); err != nil {
		t.Fatalf("unmarshal %q: %v", param, err)
	}
	return offer
}

func TestCreateCredentialOffer_ByValue(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))

	result, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}
	if result.Reference != "" {
		t.Errorf("Reference = %q, want empty for a by-value offer", result.Reference)
	}
	if result.Offer.CredentialIssuer != testIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", result.Offer.CredentialIssuer, testIssuer)
	}

	got := decodeOfferURI(t, result.URI, "credential_offer")
	if got.CredentialIssuer != result.Offer.CredentialIssuer {
		t.Errorf("decoded CredentialIssuer = %q, want %q", got.CredentialIssuer, result.Offer.CredentialIssuer)
	}
	if len(got.CredentialConfigurationIDs) != 1 || got.CredentialConfigurationIDs[0] != "IdentityCredential" {
		t.Errorf("decoded CredentialConfigurationIDs = %v", got.CredentialConfigurationIDs)
	}
}

func TestCreateCredentialOffer_ByReference(t *testing.T) {
	now := time.Now()
	cfg := validConfig(t)
	deps := validDependencies(t)
	deps.Clock = fixedClock{now: now}
	iss := newTestIssuer(t, cfg, deps)

	result, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		ByReference:                true,
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}
	if result.Reference == "" {
		t.Fatalf("Reference is empty for a by-reference offer")
	}

	if !strings.HasPrefix(result.URI, "openid-credential-offer://?") {
		t.Fatalf("URI = %q, want openid-credential-offer:// scheme", result.URI)
	}
	parsed, err := url.Parse(result.URI)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}
	offerURL := parsed.Query().Get("credential_offer_uri")
	if !strings.HasSuffix(offerURL, "/"+result.Reference) {
		t.Errorf("offer URL = %q, want suffix %q", offerURL, "/"+result.Reference)
	}
	if !strings.HasPrefix(offerURL, testCredentialOfferEndpoint) {
		t.Errorf("offer URL = %q, want prefix %q", offerURL, testCredentialOfferEndpoint)
	}

	fetched, err := iss.GetCredentialOffer(context.Background(), result.Reference)
	if err != nil {
		t.Fatalf("GetCredentialOffer: %v", err)
	}
	if fetched.CredentialIssuer != result.Offer.CredentialIssuer {
		t.Errorf("fetched CredentialIssuer = %q, want %q", fetched.CredentialIssuer, result.Offer.CredentialIssuer)
	}
}

func TestCreateCredentialOffer_ByReferenceRequiresEndpoint(t *testing.T) {
	cfg := validConfig(t)
	cfg.CredentialOfferEndpoint = fapi.URL{}
	cfg.Limits.CredentialOfferLifetime = 0
	deps := validDependencies(t)
	deps.CredentialOffers = nil
	iss := newTestIssuer(t, cfg, deps)

	_, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		ByReference:                true,
	})
	if err == nil {
		t.Fatalf("CreateCredentialOffer = nil error, want error")
	}
}

func TestCreateCredentialOffer_RejectsInvalidRequest(t *testing.T) {
	cases := map[string]issuer.CreateCredentialOfferRequest{
		"empty configuration ids": {
			CredentialConfigurationIDs: nil,
		},
		"unknown configuration id": {
			CredentialConfigurationIDs: []string{"NoSuchConfig"},
		},
		"duplicate configuration ids": {
			CredentialConfigurationIDs: []string{"IdentityCredential", "IdentityCredential"},
		},
		"empty grants": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants:                     &issuer.Grants{},
		},
		"authorization_code with authorization_server": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &issuer.Grants{
				AuthorizationCode: &issuer.GrantAuthorizationCode{AuthorizationServer: "https://as.example.com"},
			},
		},
		"pre-authorized_code missing code": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants:                     &issuer.Grants{PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{}},
		},
		"pre-authorized_code with authorization_server": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &issuer.Grants{
				PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{
					PreAuthorizedCode:   "abc123",
					AuthorizationServer: "https://as.example.com",
				},
			},
		},
		"tx_code description too long": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &issuer.Grants{
				PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{
					PreAuthorizedCode: "abc123",
					TxCode:            &issuer.TxCode{Description: strings.Repeat("x", 301)},
				},
			},
		},
		"tx_code invalid input_mode": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &issuer.Grants{
				PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{
					PreAuthorizedCode: "abc123",
					TxCode:            &issuer.TxCode{InputMode: "hex"},
				},
			},
		},
		"tx_code negative length": {
			CredentialConfigurationIDs: []string{"IdentityCredential"},
			Grants: &issuer.Grants{
				PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{
					PreAuthorizedCode: "abc123",
					TxCode:            &issuer.TxCode{Length: -1},
				},
			},
		},
	}

	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := iss.CreateCredentialOffer(context.Background(), req); err == nil {
				t.Fatalf("CreateCredentialOffer(%s) = nil error, want error", name)
			}
		})
	}
}

func TestCreateCredentialOffer_AcceptsPreAuthorizedCodeWithTxCode(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))

	result, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		Grants: &issuer.Grants{
			PreAuthorizedCode: &issuer.GrantPreAuthorizedCode{
				PreAuthorizedCode: "oaKazRN8I0IbtZ0C7JuMn5",
				TxCode: &issuer.TxCode{
					Length:      4,
					InputMode:   issuer.TxCodeInputModeNumeric,
					Description: "Please provide the one-time code that was sent via e-mail",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}

	encoded, err := json.Marshal(result.Offer)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"urn:ietf:params:oauth:grant-type:pre-authorized_code"`) {
		t.Errorf("encoded offer = %s, want the pre-authorized_code grant type URN as a key", encoded)
	}
	if !strings.Contains(string(encoded), `"pre-authorized_code":"oaKazRN8I0IbtZ0C7JuMn5"`) {
		t.Errorf("encoded offer = %s, want pre-authorized_code value", encoded)
	}
}

func TestCreateCredentialOffer_AcceptsAuthorizationCodeGrant(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))

	result, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		Grants: &issuer.Grants{
			AuthorizationCode: &issuer.GrantAuthorizationCode{IssuerState: "opaque-state"},
		},
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}
	if result.Offer.Grants == nil || result.Offer.Grants.AuthorizationCode == nil {
		t.Fatalf("Offer.Grants.AuthorizationCode is nil")
	}
	if result.Offer.Grants.AuthorizationCode.IssuerState != "opaque-state" {
		t.Errorf("IssuerState = %q, want %q", result.Offer.Grants.AuthorizationCode.IssuerState, "opaque-state")
	}
}

func TestGetCredentialOffer_RejectsUnknownReference(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	if _, err := iss.GetCredentialOffer(context.Background(), "no-such-reference"); err == nil {
		t.Fatalf("GetCredentialOffer = nil error, want error")
	}
}

func TestGetCredentialOffer_RejectsExpiredReference(t *testing.T) {
	now := time.Now()
	store := newFakeCredentialOfferStore()
	cfg := validConfig(t)
	cfg.Limits.CredentialOfferLifetime = time.Minute

	createDeps := validDependencies(t)
	createDeps.CredentialOffers = store
	createDeps.Clock = fixedClock{now: now}
	creator := newTestIssuer(t, cfg, createDeps)

	result, err := creator.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
		ByReference:                true,
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}

	laterDeps := validDependencies(t)
	laterDeps.CredentialOffers = store
	laterDeps.Clock = fixedClock{now: now.Add(2 * time.Minute)}
	later := newTestIssuer(t, cfg, laterDeps)

	if _, err := later.GetCredentialOffer(context.Background(), result.Reference); err == nil {
		t.Fatalf("GetCredentialOffer = nil error, want error (expired)")
	}
}

func TestGetCredentialOffer_RejectsWhenNotConfigured(t *testing.T) {
	cfg := validConfig(t)
	cfg.CredentialOfferEndpoint = fapi.URL{}
	cfg.Limits.CredentialOfferLifetime = 0
	deps := validDependencies(t)
	deps.CredentialOffers = nil
	iss := newTestIssuer(t, cfg, deps)

	if _, err := iss.GetCredentialOffer(context.Background(), "anything"); err == nil {
		t.Fatalf("GetCredentialOffer = nil error, want error")
	}
}

func TestCredentialOffer_WriteJSON(t *testing.T) {
	iss := newTestIssuer(t, validConfig(t), validDependencies(t))
	result, err := iss.CreateCredentialOffer(context.Background(), issuer.CreateCredentialOfferRequest{
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	})
	if err != nil {
		t.Fatalf("CreateCredentialOffer: %v", err)
	}

	rec := httptest.NewRecorder()
	result.Offer.WriteJSON(rec)
	if rec.Code != 200 {
		t.Errorf("HTTP status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	var got issuer.CredentialOffer
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal response body: %v", err)
	}
	if got.CredentialIssuer != result.Offer.CredentialIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", got.CredentialIssuer, result.Offer.CredentialIssuer)
	}
}
