package main

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

func TestStartCRL(t *testing.T) {
	f, err := conformancecrl.NewFixture("pidwallet-test-iaca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := conformancecrl.WriteFiles(f.Publisher, filepath.Join(dir, "crl-publisher-current.json"), f.Trust, filepath.Join(dir, "crl-trust.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := startCRL(context.Background(), options{work: dir, crlSet: "revoked"}); err == nil {
		t.Error("started with a CRL set pidsetup didn't write")
	}
	checker, err := startCRL(context.Background(), options{work: dir, crlSet: "current"})
	if err != nil {
		t.Fatal(err)
	}
	err = checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{f.Revoked.Cert, f.CA.Cert}})
	if !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked signer: %v, want ErrRevoked", err)
	}
}
