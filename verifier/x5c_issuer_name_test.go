package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// issuerLeaf is a leaf under ca naming uris and dnsNames.
func issuerLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, uris []string, dnsNames []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, DNSNames: dnsNames,
	}
	for _, u := range uris {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

// With RequireIssuerName, an iss must be present and name the x5c
// leaf, so another issuer's certificate under the same trusted root
// can't sign in this issuer's name.
func TestX5CIssuerKeyResolver_BindsIssToLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	r := verifier.X5CIssuerKeyResolver{Roots: roots, RequireIssuerName: true, Revocation: certrevocation.NoCheck{}}
	const trusted = "https://issuer-a.example"
	for name, tc := range map[string]struct {
		uris, dnsNames []string
		iss            any
		ok             bool
	}{
		"the leaf names iss":                 {uris: []string{trusted}, iss: trusted, ok: true},
		"no iss":                             {uris: []string{trusted}, iss: nil},
		"a dns: iss and its dNSName":         {dnsNames: []string{"issuer-a.example"}, iss: "dns:issuer-a.example", ok: true},
		"another issuer's URL":               {uris: []string{"https://issuer-b.example"}, iss: trusted},
		"only a DNS host that isn't iss's":   {dnsNames: []string{"issuer-b.example"}, iss: trusted},
		"another URL, and a host both share": {uris: []string{"https://example.com/b"}, dnsNames: []string{"example.com"}, iss: "https://example.com/a"},
		"iss isn't a string":                 {uris: []string{trusted}, iss: 42},
	} {
		leaf := issuerLeaf(t, ca, caKey, tc.uris, tc.dnsNames)
		header := map[string]any{"x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
		payload := map[string]any{}
		if tc.iss != nil {
			payload["iss"] = tc.iss
		}
		_, _, err := r.ResolveIssuerKey(context.Background(), header, payload)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}

// By default iss isn't checked against the leaf: SD-JWT VC §2.5 doesn't
// require them to correspond, and the EU reference PID issuer signs
// with an https iss from a leaf with no subject alternative name.
func TestX5CIssuerKeyResolver_IssNotBoundByDefault(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	r := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}
	for name, uris := range map[string][]string{
		"a leaf with no subject alternative name": nil,
		"a leaf naming another issuer":            {"https://issuer-b.example"},
	} {
		leaf := issuerLeaf(t, ca, caKey, uris, nil)
		header := map[string]any{"x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
		if _, _, err := r.ResolveIssuerKey(context.Background(), header, map[string]any{"iss": "https://backend.issuer.example"}); err != nil {
			t.Errorf("%s: %v, want accepted", name, err)
		}
	}
}

// ResolveIssuerChains gives the verified path from the x5c leaf to
// Roots: a certificate the header appends that isn't on it, another
// authority's CA, isn't in it, so IssuerAuthorized and
// trusted_authorities checks never see it.
func TestX5CIssuerKeyResolver_ResolveIssuerChainsIsTheVerifiedPath(t *testing.T) {
	ca, caKey := testcert.CA(t, "issuer root")
	unrelated, _ := testcert.CA(t, "another authority")
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	leaf := issuerLeaf(t, ca, caKey, nil, nil)
	header := map[string]any{"x5c": []any{
		base64.StdEncoding.EncodeToString(leaf.Raw), base64.StdEncoding.EncodeToString(unrelated.Raw),
	}}
	chains, err := verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}.ResolveIssuerChains(context.Background(), header)
	if err != nil {
		t.Fatal(err)
	}
	for _, chain := range chains {
		for _, cert := range chain {
			if cert.Equal(unrelated) {
				t.Errorf("a verified path includes the unrelated CA the header appended")
			}
		}
		if len(chain) != 2 || !chain[0].Equal(leaf) || !chain[1].Equal(ca) {
			t.Errorf("path = %d certificates, want leaf → root", len(chain))
		}
	}
}
