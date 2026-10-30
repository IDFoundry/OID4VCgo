package registration_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/dcql"
	"github.com/idfoundry/oid4vcgo/internal/jose"
	"github.com/idfoundry/oid4vcgo/registration"
)

// registrar is a test registrar: a CA, and a signing certificate it
// issued.
type registrar struct {
	roots *x509.CertPool
	key   *ecdsa.PrivateKey
	chain []*x509.Certificate
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
}

func newRegistrar(t *testing.T) registrar {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test registrar CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true,
	}, nil, &caKey.PublicKey, caKey)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registrarURI, _ := url.Parse("https://registrar.example")
	leaf := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "test registrar"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, URIs: []*url.URL{registrarURI},
	}, ca, &key.PublicKey, caKey)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return registrar{roots: roots, key: key, chain: []*x509.Certificate{leaf}, ca: ca, caKey: caKey}
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

// verify is Registrars.Verify under roots, with no revocation check.
func verify(token string, roots *x509.CertPool, clientID string, now time.Time) (registration.Registration, error) {
	return registration.Registrars{Roots: roots, Revocation: certrevocation.NoCheck{}}.Verify(context.Background(), token, clientID, now)
}

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
	got, err := verify(token, reg.roots, clientID, time.Now())
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
		if _, err := verify(c.token, c.roots, c.clientID, c.now); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error containing %q", name, err, c.want)
		}
	}
}

// A registration whose claims another parser would read differently —
// sub twice, or a case variant of it — is refused, though the
// registrar signed it.
func TestVerify_RefusesAmbiguousClaims(t *testing.T) {
	reg := newRegistrar(t)
	token, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := jose.DecodeUnverified(token)
	if err != nil {
		t.Fatal(err)
	}
	for name, prefix := range map[string]string{
		"sub twice":        `{"sub":"x509_hash:other",`,
		"case-variant sub": `{"SUB":"x509_hash:other",`,
	} {
		resigned, err := jose.Sign(jose.ES256, reg.key, header, append([]byte(prefix), payload[1:]...))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verify(resigned, reg.roots, clientID, time.Now()); err == nil {
			t.Errorf("%s: accepted", name)
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

// TestUnregisteredRevealed judges what a presentation discloses along
// with the claims asked for: a registered path covers itself and what
// sits within it, never a sibling element or member.
func TestUnregisteredRevealed(t *testing.T) {
	k, i, w := dcql.PathKey, dcql.PathIndex, dcql.Wildcard
	r := registration.Registration{Claims: []dcql.Path{{k("nationalities"), i(0)}, {k("degrees"), w, k("type")}, {k("address")}}}
	revealed := []dcql.Path{
		{k("nationalities"), i(1)},
		{k("degrees"), i(0), k("university")},
		{k("address"), k("country")},
	}
	got := r.UnregisteredRevealed(dcql.CredentialQuery{ID: "q"}, revealed)
	if len(got) != 2 || !slicesEqual(got[0], revealed[0]) || !slicesEqual(got[1], revealed[1]) {
		t.Errorf("UnregisteredRevealed = %v, want %v", got, revealed[:2])
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

// TestVerify_RegistrarCertificate: the registrar's iss must be a URI in
// its signing certificate, the certificate must be for digital
// signatures, and Registrars.LeafPolicy can refuse it — so a
// certificate merely chaining to the roots, such as a Verifier's own,
// can't vouch for anyone.
func TestVerify_RegistrarCertificate(t *testing.T) {
	reg := newRegistrar(t)
	other := shop()
	other.Registrar = "https://another-registrar.example"
	token, err := registration.Issue(other, reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(token, reg.roots, clientID, time.Now()); err == nil || !strings.Contains(err.Error(), "iss") {
		t.Errorf("an iss not in the certificate: %v, want refused", err)
	}

	good, err := registration.Issue(shop(), reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	refuse := func(*x509.Certificate, [][]*x509.Certificate) error { return errors.New("not a registrar") }
	registrars := registration.Registrars{Roots: reg.roots, LeafPolicy: refuse, Revocation: certrevocation.NoCheck{}}
	if _, err := registrars.Verify(context.Background(), good, clientID, time.Now()); err == nil || !strings.Contains(err.Error(), "not a registrar") {
		t.Errorf("a policy refusing the certificate: %v, want refused", err)
	}

	// A key-agreement-only certificate under the same roots.
	caKey, caCert := reg.caKey, reg.ca
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	registrarURI, _ := url.Parse("https://registrar.example")
	noSign := mustCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(9), Subject: pkix.Name{CommonName: "not for signing"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyAgreement, URIs: []*url.URL{registrarURI},
	}, caCert, &key.PublicKey, caKey)
	token, err = registration.Issue(shop(), key, []*x509.Certificate{noSign})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(token, reg.roots, clientID, time.Now()); err == nil || !strings.Contains(err.Error(), "digitalSignature") {
		t.Errorf("a certificate not for signing: %v, want refused", err)
	}
}

// A registration is bound to a Client Identifier: with none to bind it
// to — an unsigned DC API request has none — it isn't accepted.
func TestVerify_RefusesNoClientID(t *testing.T) {
	roots := x509.NewCertPool()
	if _, err := verify("eyJ.e30.sig", roots, "", time.Now()); err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("Verify with no client_id: %v", err)
	}
}

// The registrar's certificate is checked at the time the registration
// is, not the wall clock: one that has expired by then fails, though
// the registration itself still holds.
func TestVerify_RegistrarCertificateAtNow(t *testing.T) {
	reg := newRegistrar(t)
	r := shop()
	r.Expires = time.Now().Add(3 * time.Hour)
	token, err := registration.Issue(r, reg.key, reg.chain)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verify(token, reg.roots, clientID, time.Now()); err != nil {
		t.Fatalf("now: %v", err)
	}
	if _, err := verify(token, reg.roots, clientID, reg.chain[0].NotAfter.Add(time.Hour)); err == nil {
		t.Error("accepted a registration at a time after its registrar's certificate expired")
	}
}
