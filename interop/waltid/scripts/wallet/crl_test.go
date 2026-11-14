package main

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

func TestStartCRL(t *testing.T) {
	f, err := conformancecrl.NewFixture("waltid-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := conformancecrl.WriteFiles(f.Publisher, "crl-publisher-current.json", f.Trust, "crl-trust.json"); err != nil {
		t.Fatal(err)
	}
	if checker, err := startCRL(context.Background(), "none"); err != nil || checker != nil {
		t.Errorf("-crl-set none: %v, %v; want no checker", checker, err)
	}
	if _, err := startCRL(context.Background(), "expired"); err == nil {
		t.Error("started with a CRL set setup didn't write")
	}
	checker, err := startCRL(context.Background(), "current")
	if err != nil {
		t.Fatal(err)
	}
	err = checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{f.Revoked.Cert, f.CA.Cert}})
	if !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked certificate: %v, want ErrRevoked", err)
	}
}
