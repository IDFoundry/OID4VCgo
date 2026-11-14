package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/prodwallet"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// The leaf policies tell Issuer2's certificates from Verifier2's, both
// under the run's one CA.
func TestCommonNamePolicy(t *testing.T) {
	leaf := func(cn string) *x509.Certificate { return &x509.Certificate{Subject: pkix.Name{CommonName: cn}} }
	issuer, verifier := commonNamePolicy(issuer2Name, true), commonNamePolicy(verifier2Name, false)
	for _, c := range []struct {
		policy func(*x509.Certificate, [][]*x509.Certificate) error
		cn     string
		ok     bool
	}{
		{issuer, "walt.id Issuer2", true},
		{issuer, "walt.id Issuer2 document signer", true},
		{issuer, "walt.id Verifier2", false},
		{verifier, "walt.id Verifier2", true},
		{verifier, "walt.id Issuer2", false},
		{verifier, "walt.id Verifier2 other", false},
	} {
		if err := c.policy(leaf(c.cn), nil); (err == nil) != c.ok {
			t.Errorf("%q: %v", c.cn, err)
		}
	}
}

func TestProductionNeedsRevocationAndStores(t *testing.T) {
	cfg := walletflow.Config{VerifierTrust: wallet.X5CVerifierRoots{Roots: x509.NewCertPool()}}
	var deps walletflow.Dependencies
	if _, err := production(&cfg, &deps, options{store: t.TempDir()}, nil); err == nil {
		t.Error("production took no revocation check")
	}
	opts := options{store: t.TempDir(), allowedPrivateHosts: []string{"issuer2.example"}}
	stores, err := production(&cfg, &deps, opts, certrevocation.NoCheck{})
	if !prodwallet.Built {
		if !errors.Is(err, prodwallet.ErrNotBuilt) {
			t.Fatalf("production without the tag: %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stores.Close() })
	roots, _ := cfg.VerifierTrust.(wallet.X5CVerifierRoots)
	if cfg.Development || cfg.StatusRevocation == nil || cfg.IssuerLeafPolicy == nil || roots.LeafPolicy == nil || deps.Keys == nil || deps.HTTP != nil ||
		len(cfg.AllowedPrivateHosts) != 1 || cfg.AllowedPrivateHosts[0] != "issuer2.example" {
		t.Fatalf("production left %+v, %+v", cfg, deps)
	}
}
