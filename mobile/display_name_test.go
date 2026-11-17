package mobile

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"slices"
	"testing"
)

// A reader certificate's names — subject, issuer and alternative names,
// written by whoever made it, trusted or not — reach the app as cleaned
// as its common name does.
func TestCertificateNamesCleaned(t *testing.T) {
	c := &x509.Certificate{
		SerialNumber:   big.NewInt(1),
		Subject:        pkix.Name{CommonName: "Shop\u202e Police", Organization: []string{"Org\nTrusted: yes"}},
		Issuer:         pkix.Name{CommonName: "Root\u2028CA"},
		DNSNames:       []string{"reader\u200b.example"},
		EmailAddresses: []string{"a\u2066@example.com"},
		URIs:           []*url.URL{{Scheme: "https", Host: "x.example", Path: "/\u202epath"}},
	}
	got := certificateOf(c)
	if got.Subject != "CN=Shop Police,O=Org Trusted: yes" {
		t.Errorf("subject %q", got.Subject)
	}
	if got.Issuer != "CN=Root CA" {
		t.Errorf("issuer %q", got.Issuer)
	}
	if want := []string{"reader.example", "a@example.com", "https://x.example/%E2%80%AEpath"}; !slices.Equal(got.SubjectAltNames, want) {
		t.Errorf("subject alternative names %q, want %q", got.SubjectAltNames, want)
	}
}

// A certificate's name reaches the holder's screen without control, line
// separator or invisible format characters, bounded.
func TestDisplayName(t *testing.T) {
	for in, want := range map[string]string{
		"State Police":             "State Police",
		"State\u202e Police":       "State Police",
		"Reader\nTrusted: yes":     "Reader Trusted: yes",
		"Reader\u2028Trusted: yes": "Reader Trusted: yes",
		"Sta\u200bte Pol\ufeffice": "State Police",
		"  \u2066Isolated\u2069 ":  "Isolated",
	} {
		if got := displayName(in); got != want {
			t.Errorf("displayName(%q) = %q, want %q", in, got, want)
		}
	}
}
