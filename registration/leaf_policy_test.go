package registration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/registration"
)

// By default a registrar certificate issued for another role under the
// registrar roots — a TLS server's, an mdoc reader's, a document
// signer's — can't register a Verifier; AnyRegistrarLeaf takes it, and
// a registrar's own certificate passes either way. The deprecated Verify
// applies the default too.
func TestDefaultRegistrarLeafPolicy(t *testing.T) {
	reg := newRegistrar(t)
	registrarURI, _ := url.Parse("https://registrar.example")
	issue := func(eku []x509.ExtKeyUsage, unknown ...asn1.ObjectIdentifier) (*ecdsa.PrivateKey, *x509.Certificate) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		return key, mustCert(t, &x509.Certificate{
			SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "other role"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{registrarURI},
			ExtKeyUsage: eku, UnknownExtKeyUsage: unknown,
		}, reg.ca, &key.PublicKey, reg.caKey)
	}
	for name, tc := range map[string]struct {
		eku     []x509.ExtKeyUsage
		unknown []asn1.ObjectIdentifier
		refused bool
	}{
		"a TLS server's":                  {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, refused: true},
		"a TLS client's beside a private": {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, unknown: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}, refused: true},
		"an OCSP signer's":                {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}, refused: true},
		"an mdoc reader's":                {unknown: []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 6}}, refused: true},
		"an mDL document signer's":        {unknown: []asn1.ObjectIdentifier{{1, 0, 18013, 5, 1, 2}}, refused: true},
		"a registrar's private purpose":   {unknown: []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 1}}},
		"any purpose":                     {eku: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}},
		"no extended key usage":           {},
	} {
		t.Run(name, func(t *testing.T) {
			key, cert := issue(tc.eku, tc.unknown...)
			token, err := registration.Issue(shop(), key, []*x509.Certificate{cert})
			if err != nil {
				t.Fatal(err)
			}
			if err := registration.DefaultRegistrarLeafPolicy(cert, nil); tc.refused != (err != nil) {
				t.Errorf("DefaultRegistrarLeafPolicy = %v, want refused %v", err, tc.refused)
			}
			registrars := registration.Registrars{Roots: reg.roots, Revocation: certrevocation.NoCheck{}}
			if _, err := registrars.Verify(context.Background(), token, clientID, time.Now()); tc.refused != (err != nil) {
				t.Errorf("Registrars.Verify = %v, want refused %v", err, tc.refused)
			} else if tc.refused && !strings.Contains(err.Error(), "leaf certificate policy") {
				t.Errorf("Registrars.Verify = %v, want the leaf policy's refusal", err)
			}
			if _, err := registration.Verify(token, reg.roots, clientID, time.Now()); tc.refused != (err != nil) { //nolint:staticcheck // the deprecated wrapper applies the default too
				t.Errorf("Verify = %v, want refused %v", err, tc.refused)
			}
			registrars.LeafPolicy = registration.AnyRegistrarLeaf
			if _, err := registrars.Verify(context.Background(), token, clientID, time.Now()); err != nil {
				t.Errorf("AnyRegistrarLeaf: %v", err)
			}
		})
	}
}
