package registration_test

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

	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/registration"
)

// registrar is a test registrar: a CA, and a signing certificate it
// issued.
type registrar struct {
	roots *x509.CertPool
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
}

func newRegistrar(t *testing.T) registrar {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test registrar CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &caKey.PublicKey, caKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test registrar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &key.PublicKey, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return registrar{roots: roots, key: key, chain: []*x509.Certificate{leaf}}
}

func mustCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	if parent == nil {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func path(keys ...string) dcql.Path {
	p := make(dcql.Path, len(keys))
	for i, k := range keys {
		p[i] = dcql.PathKey(k)
	}
	return p
}

const clientID = "x509_hash:abc"

func shop() registration.Registration {
	return registration.Registration{
		Registrar: "https://registrar.example", ClientID: clientID, Name: "Corner Bottle Shop",
		Purpose: "Age checks for alcohol sales", PrivacyPolicy: "https://shop.example/privacy",
		Claims:  []dcql.Path{path("age_over_18"), path("ns", "age_over_18")},
		Expires: time.Now().Add(time.Hour),
	}
}

func TestIssueVerify_RoundTrip(t *testing.T) {
	reg := newRegistrar(t)
	token, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := registration.Verify(token, reg.roots, clientID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Corner Bottle Shop" || got.Purpose == "" || got.PrivacyPolicy != "https://shop.example/privacy" ||
		got.Registrar != "https://registrar.example" || len(got.Claims) != 2 || got.RegistrarCertificate == nil {
		t.Errorf("Verify = %+v", got)
	}
	if !got.Permits(path("ns", "age_over_18")) || got.Permits(path("family_name")) {
		t.Error("Permits doesn't match the registered paths exactly")
	}
}

// TestVerify_Refuses: a registration from another registrar, for
// another relying party, expired, or tampered with isn't accepted.
func TestVerify_Refuses(t *testing.T) {
	reg := newRegistrar(t)
	token, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	other := newRegistrar(t)
	parts := strings.Split(token, ".")
	tampered := parts[0] + "." + parts[1] + "x." + parts[2]
	for name, c := range map[string]struct {
		token, clientID string
		roots           *x509.CertPool
		now             time.Time
		want            string
	}{
		"another registrar":     {token, clientID, other.roots, time.Now(), "registrar certificate"},
		"another relying party": {token, "x509_hash:other", reg.roots, time.Now(), "another relying party"},
		"expired":               {token, clientID, reg.roots, time.Now().Add(2 * time.Hour), "expired"},
		"tampered":              {tampered, clientID, reg.roots, time.Now(), "registration"},
		"no roots":              {token, clientID, nil, time.Now(), "no registrar roots"},
	} {
		if _, err := registration.Verify(c.token, c.roots, c.clientID, c.now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, c.want)
		}
	}
}

func TestIssue_Refuses(t *testing.T) {
	reg := newRegistrar(t)
	bad := shop()
	bad.PrivacyPolicy = "http://shop.example/privacy"
	if _, err := registration.Issue(bad, reg.key, reg.chain); err == nil {
		t.Error("a non-https privacy policy was issued")
	}
	missing := shop()
	missing.Name = ""
	if _, err := registration.Issue(missing, reg.key, reg.chain); err == nil {
		t.Error("a registration without a name was issued")
	}
}

// TestUnregistered lists what a query asks beyond the registration: an
// unregistered claim, and a credential query asking for every claim.
func TestUnregistered(t *testing.T) {
	r := shop()
	q := dcql.Query{Credentials: []dcql.CredentialQuery{
		{ID: "ok", Claims: []dcql.ClaimsQuery{{Path: path("age_over_18")}}},
		{ID: "over", Claims: []dcql.ClaimsQuery{{Path: path("age_over_18")}, {Path: path("family_name")}}},
		{ID: "all"},
	}}
	got := r.Unregistered(q)
	if _, ok := got["ok"]; ok {
		t.Errorf("a registered request was flagged: %v", got["ok"])
	}
	if len(got["over"]) != 1 || !slicesEqual(got["over"][0], path("family_name")) {
		t.Errorf("over = %v, want family_name", got["over"])
	}
	if len(got["all"]) != 1 || got["all"][0] != nil {
		t.Errorf("all = %v, want every claim flagged", got["all"])
	}
}

func slicesEqual(a, b dcql.Path) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
