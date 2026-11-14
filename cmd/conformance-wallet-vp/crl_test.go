package main

import (
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestVerifierCRL checks verifier_crl, with crl_publisher serving the
// CRL, accepts the Verifier's good certificate and refuses the one its
// CA revoked.
func TestVerifierCRL(t *testing.T) {
	f, err := conformancecrl.NewFixture("wallet-vp-test-verifier-ca")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{VerifierTrustAnchorsPEM: f.CA.CertPEM, VerifierCRL: &f.Trust, CRLPublisher: &f.Publisher}
	revocation, err := startVerifierCRL(cfg)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := cfg.verifierTrust(revocation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trust.VerifyVerifierChain([][]byte{f.Good.Cert.Raw}); err != nil {
		t.Errorf("good certificate: %v", err)
	}
	if _, err := trust.VerifyVerifierChain([][]byte{f.Revoked.Cert.Raw}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked certificate: %v, want ErrRevoked", err)
	}
	if revocation, err := startVerifierCRL(Config{}); err != nil || revocation != nil {
		t.Errorf("no verifier_crl: %v, %v; want no checker", revocation, err)
	}
}
