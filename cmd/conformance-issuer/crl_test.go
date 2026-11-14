package main

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/fapigo/server"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestCRL checks crl, with crl_publisher serving the CRL, has the
// attester and key attestation checks accept the good certificate and
// refuse the one its CA revoked, and that without it both decline.
func TestCRL(t *testing.T) {
	if _, ok := (Config{}).attesterRevocation().(server.NoClientCertificateRevocationCheck); !ok {
		t.Error("without crl, the attester check isn't declined")
	}
	if _, ok := (Config{}).keyAttestationRevocation().(certrevocation.NoCheck); !ok {
		t.Error("without crl, the key attestation check isn't declined")
	}
	f, err := conformancecrl.NewFixture("issuer-test-attester-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{CRL: &f.Trust, CRLPublisher: &f.Publisher}
	if err := cfg.startCRL(context.Background()); err != nil {
		t.Fatal(err)
	}
	chain := func(leaf *x509.Certificate) []*x509.Certificate { return []*x509.Certificate{leaf, f.CA.Cert} }
	attester := func(leaf *x509.Certificate) error {
		return cfg.attesterRevocation().CheckRevocation(context.Background(), server.ClientCertificateRevocationCheck{Chain: chain(leaf), Now: time.Now()})
	}
	if err := attester(f.Good.Cert); err != nil {
		t.Errorf("good attester certificate: %v", err)
	}
	if err := attester(f.Revoked.Cert); !errors.Is(err, server.ErrCertificateRevoked) {
		t.Errorf("revoked attester certificate: %v, want ErrCertificateRevoked", err)
	}
	keyAttestation := func(leaf *x509.Certificate) error {
		return cfg.keyAttestationRevocation().CheckRevocation(context.Background(), certrevocation.Check{Chain: chain(leaf)})
	}
	if err := keyAttestation(f.Good.Cert); err != nil {
		t.Errorf("good key attestation certificate: %v", err)
	}
	if err := keyAttestation(f.Revoked.Cert); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked key attestation certificate: %v, want ErrRevoked", err)
	}
}
