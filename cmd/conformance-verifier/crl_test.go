package main

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestIssuerCRL checks issuer_crl, with crl_publisher serving the CRL,
// accepts the issuer's good certificate and refuses the one its CA
// revoked, and that without it revocation is declined.
func TestIssuerCRL(t *testing.T) {
	if _, ok := (Config{}).revocation().(certrevocation.NoCheck); !ok {
		t.Error("without issuer_crl, revocation isn't NoCheck")
	}
	f, err := conformancecrl.NewFixture("verifier-test-issuer-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{IssuerCRL: &f.Trust, CRLPublisher: &f.Publisher}
	if err := cfg.startIssuerCRL(context.Background()); err != nil {
		t.Fatal(err)
	}
	check := func(leaf *x509.Certificate) error {
		return cfg.revocation().CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf, f.CA.Cert}})
	}
	if err := check(f.Good.Cert); err != nil {
		t.Errorf("good certificate: %v", err)
	}
	if err := check(f.Revoked.Cert); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked certificate: %v, want ErrRevoked", err)
	}
}
