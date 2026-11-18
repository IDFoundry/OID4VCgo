package certchain

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestNameConstraints_EachTypeConfinesItsOwnNames pins what the name
// binding docs (CheckIssuerName and its callers, SECURITY.md) say a
// name-constrained CA does and doesn't confine. RFC 5280 §4.2.1.10
// applies each constraint type to subject alternative names of its own
// type, and crypto/x509 follows it: a CA confined to a dNSName subtree
// can't certify another DNS name, but can certify any URI, so a URI
// iss (CheckIssuerName for anything but "dns:") is held to it only by
// uniformResourceIdentifier constraints. Those confine a URI's host,
// not its path.
func TestNameConstraints_EachTypeConfinesItsOwnNames(t *testing.T) {
	now := time.Now()
	newKey := func() *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	rootKey := newKey()
	root := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "trust list root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &rootKey.PublicKey, rootKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)

	// Provider A's CA, as a trust list confines a member's: by dNSName
	// only, or by URI too.
	memberCA := func(serial int64, uriDomains []string) (*x509.Certificate, *ecdsa.PrivateKey) {
		key := newKey()
		return mustCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "provider A CA"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
			PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{"provider-a.example"},
			PermittedURIDomains: uriDomains,
		}, root, &key.PublicKey, rootKey), key
	}
	dnsOnly, dnsOnlyKey := memberCA(2, nil)
	dnsAndURI, dnsAndURIKey := memberCA(3, []string{"provider-a.example"})

	leafKey := newKey()
	leaf := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey, dns, uri string) []byte {
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "signer"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		}
		if dns != "" {
			tmpl.DNSNames = []string{dns}
		}
		if uri != "" {
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			tmpl.URIs = []*url.URL{u}
		}
		return mustCert(t, tmpl, ca, &leafKey.PublicKey, caKey).Raw
	}

	for _, tc := range []struct {
		name     string
		ca       *x509.Certificate
		caKey    *ecdsa.PrivateKey
		dns, uri string
		iss      string // "" when the chain must be refused
	}{
		{"dNSName constraint, own DNS name", dnsOnly, dnsOnlyKey, "provider-a.example", "", "dns:provider-a.example"},
		{"dNSName constraint, another's DNS name", dnsOnly, dnsOnlyKey, "provider-b.example", "", ""},
		// The dNSName constraint doesn't reach a URI, so the binding
		// accepts provider A's CA naming provider B.
		{"dNSName constraint, another's URI", dnsOnly, dnsOnlyKey, "", "https://provider-b.example", "https://provider-b.example"},
		{"URI constraint, own URI", dnsAndURI, dnsAndURIKey, "", "https://provider-a.example", "https://provider-a.example"},
		{"URI constraint, another's URI", dnsAndURI, dnsAndURIKey, "", "https://provider-b.example", ""},
		// A URI constraint confines the host, not the path.
		{"URI constraint, another path on its own host", dnsAndURI, dnsAndURIKey, "", "https://provider-a.example/tenant-b", "https://provider-a.example/tenant-b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := VerifyChainsAt([][]byte{leaf(tc.ca, tc.caKey, tc.dns, tc.uri), tc.ca.Raw}, roots, time.Time{})
			if tc.iss == "" {
				if err == nil || !strings.Contains(err.Error(), "not authorized to sign for this name") {
					t.Fatalf("got %v, want the chain refused by the CA's name constraints", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("the chain was refused: %v", err)
			}
			if err := CheckIssuerName(got, tc.iss); err != nil {
				t.Fatalf("CheckIssuerName(%q): %v", tc.iss, err)
			}
		})
	}
}
