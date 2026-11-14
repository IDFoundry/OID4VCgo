package conformancecrl_test

import (
	"context"
	"crypto/x509"
	"errors"
	"path/filepath"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecrl"
)

// TestStartFiles checks a Fixture written out and started from its
// files accepts its good leaf and refuses its revoked one.
func TestStartFiles(t *testing.T) {
	f, err := conformancecrl.NewFixture("files-test-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pub, trust := filepath.Join(dir, "pub.json"), filepath.Join(dir, "trust.json")
	if err := conformancecrl.WriteFiles(f.Publisher, pub, f.Trust, trust); err != nil {
		t.Fatal(err)
	}
	if _, err := conformancecrl.StartFiles(context.Background(), filepath.Join(dir, "missing.json"), trust, t.Logf); err == nil {
		t.Error("started without a publisher file")
	}
	checker, err := conformancecrl.StartFiles(context.Background(), pub, trust, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	check := func(leaf *x509.Certificate) error {
		return checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{leaf, f.CA.Cert}})
	}
	if err := check(f.Good.Cert); err != nil {
		t.Errorf("good leaf: %v", err)
	}
	if err := check(f.Revoked.Cert); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked leaf: %v, want ErrRevoked", err)
	}
}
