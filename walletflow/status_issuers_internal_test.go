package walletflow

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

func namedCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, uri string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return certForKey(t, ca, caKey, &key.PublicKey, uri)
}

// certForKey is a certificate under ca for pub, naming uri, or nothing
// when uri is "".
func certForKey(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, pub *ecdsa.PublicKey, uri string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// A credential's status list may be signed by its issuer, with the key
// that signed the credential or by a certificate naming it, or by one
// of the Status Issuers Config.StatusIssuers names for that issuer, and
// no one else.
func TestStatusOptionsFor(t *testing.T) {
	ca, caKey := testcert.CA(t, "shared root")
	const issuerA, statusIssuer, issuerB = "https://issuer-a.example", "https://status.example", "https://issuer-b.example"
	a, status, b := namedCert(t, ca, caKey, issuerA), namedCert(t, ca, caKey, statusIssuer), namedCert(t, ca, caKey, issuerB)
	// The credential's signer names no one, as the EU reference PID
	// issuer's certificate doesn't; its status list is signed with the
	// same key from another certificate that names no one either.
	credentialKey := b.PublicKey.(*ecdsa.PublicKey)
	sameKeyNoName := certForKey(t, ca, caKey, credentialKey, "")
	otherKeyNoName := namedCertNoURI(t, ca, caKey)

	// Without Status Issuers, the token must be the issuer's.
	if opts := statusOptionsFor(statuslist.VerifyOptions{}, issuerA, credentialKey, nil); opts.Issuer != issuerA || opts.IssuerKey != credentialKey || opts.UnboundSigner != nil {
		t.Errorf("no Status Issuers: %+v, want Issuer and IssuerKey set and no UnboundSigner", opts)
	}
	opts := statusOptionsFor(statuslist.VerifyOptions{}, issuerA, credentialKey, []string{statusIssuer})
	for name, tc := range map[string]struct {
		leaf *x509.Certificate
		ok   bool
	}{
		"the issuer, by name":                 {a, true},
		"the issuer, by the credential's key": {sameKeyNoName, true},
		"its Status Issuer":                   {status, true},
		"another issuer":                      {namedCert(t, ca, caKey, "https://issuer-c.example"), false},
		"another key, naming no one":          {otherKeyNoName, false},
	} {
		if err := opts.UnboundSigner(tc.leaf, nil); (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok = %v", name, err, tc.ok)
		}
	}
}

func namedCertNoURI(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return certForKey(t, ca, caKey, &key.PublicKey, "")
}

// signerKey reads an SD-JWT VC's x5c leaf key, and has none for a
// credential it can't read one from.
func TestSignerKey(t *testing.T) {
	for name, credential := range map[string]string{
		"not a JWT":              "junk~",
		"no x5c":                 "eyJhbGciOiJFUzI1NiJ9.e30.c2ln~",
		"an x5c that isn't DER":  "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJBQUFBIl19.e30.c2ln~",
		"an x5c that's no array": "eyJhbGciOiJFUzI1NiIsIng1YyI6IkFBQUEifQ.e30.c2ln~",
	} {
		if got := signerKey(credential); got != nil {
			t.Errorf("%s: %v, want nil", name, got)
		}
	}
}
