//go:build conformance_production

package prodwallet_test

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The stores survive being reopened, declare durable custody, and are
// what walletflow requires to receive credentials at production
// assurance.
func TestOpenIsDurable(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	s, err := prodwallet.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.Keys.NewKey(ctx, walletflow.KeyPurposeHolder)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Custody.Durable || !s.Authorizations.Durable() || !s.Grants.Durable() {
		t.Fatalf("custody %+v, authorizations durable %v, grants durable %v", s.Custody, s.Authorizations.Durable(), s.Grants.Durable())
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = prodwallet.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Keys.Key(ctx, k.ID()); err != nil {
		t.Fatalf("the key after reopening: %v", err)
	}

	roots := x509.NewCertPool()
	ca, _ := testcert.CA(t, "issuer-ca")
	roots.AddCert(ca)
	cfg := walletflow.Config{
		ClientID: "wallet", RedirectURI: "com.example.wallet:/callback",
		IssuerRoots: roots, IssuerRevocation: certrevocation.NoCheck{}, StatusRevocation: certrevocation.NoCheck{},
	}
	if _, err := walletflow.New(cfg, s.Dependencies(walletflow.Dependencies{})); err != nil {
		t.Fatalf("walletflow at production assurance: %v", err)
	}
	if _, err := walletflow.New(cfg, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()}); err == nil {
		t.Fatal("walletflow took memory stores at production assurance: the check above shows nothing")
	}
}
