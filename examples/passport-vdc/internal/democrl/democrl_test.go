package democrl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democrl"
)

func newCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// TestCA_NumbersNeverGoBack: a list is served again until half its
// validity passes or a certificate is revoked; each new one takes a
// higher CRL number, across a restart too, and lists what was revoked.
func TestCA_NumbersNeverGoBack(t *testing.T) {
	ca, key := newCA(t)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := democert.Create(&x509.Certificate{Subject: pkix.Name{CommonName: "leaf"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "crl.json")
	now := time.Now()
	clock := func() time.Time { return now }
	c, err := democrl.Open(path, ca, key, clock)
	if err != nil {
		t.Fatal(err)
	}
	first, err := c.List()
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := c.List(); again != first {
		t.Error("a second request signed a new list")
	}
	now = now.Add(democrl.Validity / 2)
	second, err := c.List()
	if err != nil || second.Number.Cmp(first.Number) <= 0 {
		t.Fatalf("after half its validity: number %v, want past %v (%v)", second.Number, first.Number, err)
	}
	if err := c.Revoke(leaf); err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(leaf); err != nil || len(c.Revoked()) != 1 {
		t.Errorf("revoking twice: %v, %d entries", err, len(c.Revoked()))
	}

	restarted, err := democrl.Open(path, ca, key, clock)
	if err != nil {
		t.Fatal(err)
	}
	third, err := restarted.List()
	if err != nil {
		t.Fatal(err)
	}
	if third.Number.Cmp(second.Number) <= 0 || len(third.RevokedCertificateEntries) != 1 || third.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Errorf("after a restart: number %v (want past %v), entries %v", third.Number, second.Number, third.RevokedCertificateEntries)
	}
	// What a relying party accepts: the CA's own, current list,
	// refusing the leaf.
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return []*x509.RevocationList{third}, nil }}
	if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf, ca}, Now: now}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("certrevocation.CRLs on the list: %v, want ErrRevoked", err)
	}
}

// TestCA_RefusesAnotherCAsCertificate: a certificate the CA didn't issue
// isn't added to its list.
func TestCA_RefusesAnotherCAsCertificate(t *testing.T) {
	ca, key := newCA(t)
	other, _ := newCA(t)
	c, err := democrl.Open("", ca, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(other); err == nil {
		t.Error("another CA's certificate was revoked")
	}
}

// TestOpen_IgnoresAnotherCAsState: a state file left by another CA
// starts the list afresh rather than revoking its serials here.
func TestOpen_IgnoresAnotherCAsState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crl.json")
	first, firstKey := newCA(t)
	c, err := democrl.Open(path, first, firstKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Revoke(first); err != nil {
		t.Fatal(err)
	}
	second, secondKey := newCA(t)
	fresh, err := democrl.Open(path, second, secondKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(fresh.Revoked()) != 0 {
		t.Error("another CA's revocations were kept")
	}
}
