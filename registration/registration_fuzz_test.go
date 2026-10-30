package registration_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/registration"
)

// fuzzRegistrar is newRegistrar for a fuzz target: a CA, and a
// registrar certificate it issued, valid around now.
func fuzzRegistrar(f *testing.F, now time.Time) (*x509.CertPool, *ecdsa.PrivateKey, []*x509.Certificate) {
	f.Helper()
	cert := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		if parent == nil {
			parent = tmpl
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			f.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			f.Fatal(err)
		}
		return c
	}
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := cert(&x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fuzz registrar CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &caKey.PublicKey, caKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	uri, _ := url.Parse("https://registrar.example")
	leaf := cert(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "fuzz registrar"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{uri},
	}, ca, &key.PublicKey, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots, key, []*x509.Certificate{leaf}
}

// fuzzQuery is a Credential Query to ask a verified registration about.
func fuzzQuery(f *testing.F) dcql.CredentialQuery {
	f.Helper()
	meta, err := dcql.NewSDJWTVCMeta(dcql.SDJWTVCMeta{VCTValues: []string{"urn:example:pid"}})
	if err != nil {
		f.Fatal(err)
	}
	return dcql.CredentialQuery{ID: "pid", Format: "dc+sd-jwt", Meta: meta}
}

// FuzzVerifyRegistration feeds arbitrary strings, as a registration
// arrives in an untrusted Verifier's verifier_info, to Registrars.Verify.
func FuzzVerifyRegistration(f *testing.F) {
	now := time.Now()
	roots, key, chain := fuzzRegistrar(f, now)
	r := shop()
	r.Expires = now.Add(30 * time.Minute)
	token, err := registration.Issue(r, key, chain)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(token)
	f.Add(token[:len(token)/2])
	f.Add(strings.Replace(token, ".", "..", 1))
	f.Add("")
	f.Add("a.b.c")
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = verify(s, roots, clientID, now)
	})
}

// FuzzVerifyRegistrationSigned signs arbitrary claims with a trusted
// registrar's key and certificate, so they reach claims parsing, and
// asks what a verified registration permits.
func FuzzVerifyRegistrationSigned(f *testing.F) {
	now := time.Now()
	roots, key, chain := fuzzRegistrar(f, now)
	cq := fuzzQuery(f)
	r := shop()
	r.Expires = now.Add(30 * time.Minute)
	token, err := registration.Issue(r, key, chain)
	if err != nil {
		f.Fatal(err)
	}
	_, payload, err := jose.DecodeUnverified(token)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(payload)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"iss":"https://registrar.example","sub":"x509_hash:abc","name":"n","iat":1,"exp":9999999999,"claims":[[null,0,"a"]]}`))
	f.Add([]byte(`{"iss":"https://registrar.example","sub":"x509_hash:abc","name":"n","iat":1,"exp":9999999999,"credentials":[{"format":"dc+sd-jwt","meta":{"vct_values":["urn:example:pid"]},"claims":[["a"]]}]}`))
	f.Add([]byte(`{"claims":"not an array","exp":"tomorrow"}`))
	x5c := []any{base64.StdEncoding.EncodeToString(chain[0].Raw)}
	header := map[string]any{"typ": registration.Type, "x5c": x5c}
	f.Fuzz(func(t *testing.T, claims []byte) {
		signed, err := jose.Sign(jose.ES256, key, header, claims)
		if err != nil {
			t.Skip()
		}
		reg, err := verify(signed, roots, clientID, now)
		if err != nil {
			return
		}
		for _, p := range []dcql.Path{{dcql.PathKey("age_over_18")}, {dcql.PathKey("ns"), dcql.PathKey("age_over_18")}, {dcql.Wildcard}, {dcql.PathIndex(0)}} {
			_ = reg.PermitsFor(cq, p)
		}
	})
}
