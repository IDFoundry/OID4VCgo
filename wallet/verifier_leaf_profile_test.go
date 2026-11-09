package wallet_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// A Request Object signed under a certificate that chains to a trusted
// root but can't be a Verifier's signing certificate — a CA
// certificate, or one whose key usage doesn't allow signing — is
// refused.
func TestParseAuthorizationRequest_RefusesSignerThatIsNotAVerifierLeaf(t *testing.T) {
	f := newRequestFixture(t)
	for name, tc := range map[string]struct {
		tmpl x509.Certificate
		want string // "" accepted
	}{
		"a signing leaf": {x509.Certificate{KeyUsage: x509.KeyUsageDigitalSignature}, ""},
		"no key usage":   {x509.Certificate{}, ""},
		"a CA": {x509.Certificate{
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
		}, "CA certificate"},
		"key encipherment only": {x509.Certificate{KeyUsage: x509.KeyUsageKeyEncipherment}, "digitalSignature"},
	} {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := tc.tmpl
		tmpl.SerialNumber, tmpl.Subject = big.NewInt(time.Now().UnixNano()), pkix.Name{CommonName: "verifier " + name}
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, &tmpl, f.caCert, &key.PublicKey, f.caKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		clientID := x509Hash(cert)
		object := f.sign(t, key, func(h map[string]any) { h["x5c"] = x5cOfCerts(cert) }, func(p map[string]any) { p["client_id"] = clientID })
		_, err = wallet.ParseAuthorizationRequest(wallet.ParseAuthorizationRequestParams{RequestObject: object, ClientID: clientID, VerifierTrust: f.trust})
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v, want accepted", name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: err = %v, want one mentioning %q", name, err, tc.want)
		}
	}
}
