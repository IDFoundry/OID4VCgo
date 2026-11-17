package walletflow_test

import (
	"context"
	"crypto/x509"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
)

// IssuerRevocation refuses, on receipt, a credential of either format
// whose issuer's signing certificate is revoked, and receives it with a
// clean CRL or none.
func TestIssuerRevocation(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{})
	crls := func(revoked bool) certrevocation.Checker {
		list, err := f.env.IssuerCRL(revoked)
		if err != nil {
			t.Fatal(err)
		}
		return testcert.ListsOf(list)
	}
	for _, c := range []testcert.RevocationCase{
		{Name: "nil"},
		{Name: "clean", Checker: crls(false)},
		{Name: "revoked", Checker: crls(true), Want: certrevocation.ErrRevoked},
	} {
		w, err := walletflow.New(walletflow.Config{
			ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
			CredentialIssuers: []string{f.env.IssuerURL}, IssuerRoots: f.env.IssuerRoots, IssuerRevocation: c.Checker,
		}, walletflow.Dependencies{
			Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: f.env.Provider, HTTP: f.env.HTTP,
		})
		if err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		for _, configID := range []string{walletflowtest.SDJWTConfigurationID, walletflowtest.MdocConfigurationID} {
			t.Run(c.Name+"/"+configID, func(t *testing.T) {
				c.Check(t, tryReceive(t, f, w, configID))
			})
		}
	}
}

// revokingChecker refuses every chain as revoked, counting them.
type revokingChecker struct{ checks *atomic.Int32 }

func (c revokingChecker) CheckRevocation(context.Context, certrevocation.Check) error {
	c.checks.Add(1)
	return certrevocation.ErrRevoked
}

// A copy of a batch is checked against its issuer once, not once per
// holder key it might be bound to.
func TestIssuerRevocation_CheckedOncePerCopy(t *testing.T) {
	f := newFixture(t, walletflowtest.Options{BatchSize: 3})
	var checks atomic.Int32
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, Development: true,
		CredentialIssuers: []string{f.env.IssuerURL}, IssuerRoots: f.env.IssuerRoots, IssuerRevocation: revokingChecker{&checks},
	}, walletflow.Dependencies{
		Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore(), Provider: f.env.Provider, HTTP: f.env.HTTP,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tryReceive(t, f, w, walletflowtest.SDJWTConfigurationID); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Fatalf("err = %v, want the issuer revoked", err)
	}
	if got := checks.Load(); got != 1 {
		t.Errorf("issuer chain checked %d times for the first copy of 3, want 1", got)
	}
}

// New refuses a role's revocation Checker that can't check anything.
func TestNew_RefusesIncompleteRevocation(t *testing.T) {
	for name, set := range map[string]func(*walletflow.Config){
		"IssuerRevocation":         func(c *walletflow.Config) { c.IssuerRevocation = certrevocation.CRLs{} },
		"StatusRevocation":         func(c *walletflow.Config) { c.StatusRevocation = certrevocation.CRLs{} },
		"IssuerMetadataRevocation": func(c *walletflow.Config) { c.IssuerMetadataRevocation = certrevocation.CRLs{} },
		"RegistrarRevocation":      func(c *walletflow.Config) { c.RegistrarRevocation = certrevocation.CRLs{} },
		"MdocReaderRevocation":     func(c *walletflow.Config) { c.MdocReaderRevocation = certrevocation.CRLs{} },
	} {
		cfg := walletflow.Config{Development: true, CredentialIssuers: []string{"https://issuer.example"}, IssuerRoots: x509.NewCertPool()}
		set(&cfg)
		_, err := walletflow.New(cfg, walletflow.Dependencies{Keys: walletflow.NewMemoryKeyStore(), Credentials: walletflow.NewMemoryCredentialStore()})
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v, want it refused", name, err)
		}
	}
}
