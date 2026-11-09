package wallet_test

import (
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Wallet given its own HTTP client still refuses, before sending
// anything, to fetch a request_uri or credential_offer_uri on a
// loopback or private address unless Config.Fetch allows it: both URIs
// come from a link anyone can make, and could otherwise reach the
// device's own services.
func TestWallet_FetchRefusesInternalAddressesWithItsOwnClient(t *testing.T) {
	sent := 0
	deps := validDependencies()
	deps.HTTP = fakeHTTPClient{do: func(*http.Request) (*http.Response, error) {
		sent++
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader(""))}, nil
	}}
	cfg := validConfig()
	cfg.Fetch.AllowLoopbackHTTP = false
	cfg.VerifierTrust = wallet.NoVerifierTrust{}
	w, err := wallet.New(cfg, deps)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{
		netip.AddrFrom4([4]byte{127, 0, 0, 1}).String(),
		"localhost",
		"[" + netip.IPv6Loopback().String() + "]",
		netip.AddrFrom4([4]byte{10, 0, 0, 1}).String(),
		netip.AddrFrom4([4]byte{169, 254, 169, 254}).String(),
	} {
		for _, scheme := range []string{"http", "https"} {
			uri := scheme + "://" + host + "/x"
			if _, err := w.FetchAuthorizationRequest(t.Context(), uri, "x509_hash:abc"); err == nil || !strings.Contains(err.Error(), "fapihttp") {
				t.Errorf("FetchAuthorizationRequest(%s) = %v, want the fetcher's refusal", uri, err)
			}
			offer := "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(uri)
			if _, err := w.ResolveCredentialOffer(t.Context(), offer); err == nil || !strings.Contains(err.Error(), "fapihttp") {
				t.Errorf("ResolveCredentialOffer(%s) = %v, want the fetcher's refusal", uri, err)
			}
		}
	}
	if sent != 0 {
		t.Errorf("%d requests sent, want none", sent)
	}
	// The same Wallet fetches from a public address: the client is asked.
	// An address, not a name, so the check needs no DNS.
	public := "https://" + netip.AddrFrom4([4]byte{93, 184, 215, 14}).String()
	if _, err := w.FetchAuthorizationRequest(t.Context(), public+"/x", "x509_hash:abc"); err == nil || sent != 1 {
		t.Errorf("a public request_uri: err %v after %d requests, want the client's 404 after 1", err, sent)
	}
	if _, err := w.ResolveCredentialOffer(t.Context(), "openid-credential-offer://?credential_offer_uri="+url.QueryEscape(public+"/offer")); err == nil || sent != 2 {
		t.Errorf("a public credential_offer_uri: err %v after %d requests, want the client's 404 after 2", err, sent)
	}
}
