package wallet_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcigo"
	"github.com/idfoundry/oid4vcigo/wallet"
)

func testOffer() oid4vci.CredentialOffer {
	return oid4vci.CredentialOffer{
		CredentialIssuer:           "https://issuer.example.com",
		CredentialConfigurationIDs: []string{"IdentityCredential"},
	}
}

// jsonResponse builds an *http.Response with body, a 200 status, and
// an application/json Content-Type.
func jsonResponse(body []byte) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func newTestWallet(t *testing.T, do func(*http.Request) (*http.Response, error)) *wallet.Wallet {
	t.Helper()
	w, err := wallet.New(validConfig(), wallet.Dependencies{
		HTTP:  fakeHTTPClient{do: do},
		Clock: wallet.ClockFunc(time.Now),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func TestResolveCredentialOffer_ByValue(t *testing.T) {
	offer := testOffer()
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(encoded))

	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call for a by-value offer")
		return nil, nil
	})

	got, err := w.ResolveCredentialOffer(context.Background(), uri)
	if err != nil {
		t.Fatalf("ResolveCredentialOffer: %v", err)
	}
	if got.CredentialIssuer != offer.CredentialIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", got.CredentialIssuer, offer.CredentialIssuer)
	}
}

func TestResolveCredentialOffer_ByReference(t *testing.T) {
	offer := testOffer()
	encoded, err := json.Marshal(offer)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	offerURL := "http://localhost/credential-offer/abc123"
	uri := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURL)

	var calledURL string
	w := newTestWallet(t, func(req *http.Request) (*http.Response, error) {
		calledURL = req.URL.String()
		return jsonResponse(encoded), nil
	})

	got, err := w.ResolveCredentialOffer(context.Background(), uri)
	if err != nil {
		t.Fatalf("ResolveCredentialOffer: %v", err)
	}
	if got.CredentialIssuer != offer.CredentialIssuer {
		t.Errorf("CredentialIssuer = %q, want %q", got.CredentialIssuer, offer.CredentialIssuer)
	}
	if calledURL != offerURL {
		t.Errorf("fetched URL = %q, want %q", calledURL, offerURL)
	}
}

func TestResolveCredentialOffer_RejectsBothPresent(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	uri := "openid-credential-offer://?credential_offer=%7B%7D&credential_offer_uri=http://localhost/x"
	if _, err := w.ResolveCredentialOffer(context.Background(), uri); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}

func TestResolveCredentialOffer_RejectsNeitherPresent(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	if _, err := w.ResolveCredentialOffer(context.Background(), "openid-credential-offer://?"); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}

func TestResolveCredentialOffer_RejectsMalformedURI(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	if _, err := w.ResolveCredentialOffer(context.Background(), "://not a uri"); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}

func TestResolveCredentialOffer_RejectsInvalidJSON(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape("not json")
	if _, err := w.ResolveCredentialOffer(context.Background(), uri); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}

func TestResolveCredentialOffer_RejectsStructurallyInvalidOffer(t *testing.T) {
	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		t.Fatalf("unexpected HTTP call")
		return nil, nil
	})
	// credential_configuration_ids is empty — fails oid4vci.CredentialOffer.Validate.
	invalid := `{"credential_issuer":"https://issuer.example.com","credential_configuration_ids":[]}`
	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(invalid)
	if _, err := w.ResolveCredentialOffer(context.Background(), uri); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}

func TestResolveCredentialOffer_PropagatesFetchError(t *testing.T) {
	offerURL := "http://localhost/credential-offer/abc123"
	uri := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(offerURL)

	w := newTestWallet(t, func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("simulated network failure")
	})
	if _, err := w.ResolveCredentialOffer(context.Background(), uri); err == nil {
		t.Fatalf("ResolveCredentialOffer = nil error, want error")
	}
}
