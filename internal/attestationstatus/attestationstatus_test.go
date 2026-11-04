package attestationstatus_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/attestationstatus"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/internal/teststatuslist"
	"github.com/idfoundry/oid4vcgo/statuslist"
)

var errRefused = errors.New("refused")

// provider is a Wallet Provider: its own CA under the shared root, the
// certificate it signs attestations with, and another for status lists.
type provider struct {
	ca                       *x509.Certificate
	attester, statusSigner   *x509.Certificate
	attesterKey, statusKey   *ecdsa.PrivateKey
	attesterPath, statusPath []*x509.Certificate
}

// pki is two Wallet Providers under one shared root.
type pki struct {
	roots *x509.CertPool
	a, b  provider
}

func newPKI(t *testing.T) pki {
	t.Helper()
	root, rootKey := testcert.CA(t, "shared trust list root")
	roots := x509.NewCertPool()
	roots.AddCert(root)
	newProvider := func(name string) provider {
		ca, caKey := testcert.Intermediate(t, name+" CA", root, rootKey)
		p := provider{ca: ca}
		p.attester, p.attesterKey = testcert.Leaf(t, name+" attester", ca, caKey)
		p.statusSigner, p.statusKey = testcert.Leaf(t, name+" status lists", ca, caKey)
		p.attesterPath = []*x509.Certificate{p.attester, ca}
		p.statusPath = []*x509.Certificate{p.statusSigner, ca}
		return p
	}
	return pki{roots: roots, a: newProvider("provider A"), b: newProvider("provider B")}
}

// attestation is one signed by p's attester, whose status is entry idx
// on srv's list.
func (p provider) attestation(srv *teststatuslist.JWTServer, idx int) attestationstatus.Attestation {
	return attestationstatus.Attestation{
		Status: srv.Claim(idx), HasStatus: true,
		SignerKey: &p.attesterKey.PublicKey, SignerCertificates: p.attesterPath,
	}
}

func policy(k pki, srv *teststatuslist.JWTServer) attestationstatus.Policy {
	return attestationstatus.Policy{Checker: statuslist.Checker{Fetcher: srv.Fetcher, Roots: k.roots}}
}

type outcome int

const (
	valid outcome = iota
	refused
	undecided
)

func (o outcome) check(t *testing.T, err error) {
	t.Helper()
	switch {
	case o == valid && err != nil:
		t.Errorf("err = %v, want nil", err)
	case o == refused && !errors.Is(err, errRefused):
		t.Errorf("err = %v, want one wrapping the refusal", err)
	case o == undecided && (err == nil || errors.Is(err, errRefused)):
		t.Errorf("err = %v, want an error not wrapping the refusal", err)
	}
}

func TestCheck_Statuses(t *testing.T) {
	k := newPKI(t)
	srv := teststatuslist.ServeJWT(t)
	srv.Publish(t, k.a.attesterKey, k.a.attesterPath, 0, uint8(statuslist.StatusInvalid), uint8(statuslist.StatusSuspended), 3)
	p := policy(k, srv)
	for idx, want := range []outcome{valid, refused, refused, refused} {
		err := p.Check(context.Background(), k.a.attestation(srv, idx), errRefused)
		want.check(t, err)
		if want == refused {
			var notValid *statuslist.NotValidError
			if !errors.As(err, &notValid) || notValid.Status != statuslist.StatusType(idx) {
				t.Errorf("entry %d: err = %v, want a *statuslist.NotValidError for status %d", idx, err, idx)
			}
		}
	}
}

// TestCheck_ListSignerBinding: a list signed by another Wallet Provider
// under the same roots decides nothing; one signed under the
// attester's own CA by another certificate only with
// ListSignerUnderAttesterCA.
func TestCheck_ListSignerBinding(t *testing.T) {
	k := newPKI(t)
	for name, tc := range map[string]struct {
		key        crypto.Signer
		chain      []*x509.Certificate
		sameKey    outcome
		underCA    outcome
		attestedBy []*x509.Certificate
	}{
		"the attester's own key":                 {k.a.attesterKey, k.a.attesterPath, valid, valid, k.a.attesterPath},
		"another provider's attester":            {k.b.attesterKey, k.b.attesterPath, undecided, undecided, k.a.attesterPath},
		"another provider's status signer":       {k.b.statusKey, k.b.statusPath, undecided, undecided, k.a.attesterPath},
		"the attester CA's status signer":        {k.a.statusKey, k.a.statusPath, undecided, valid, k.a.attesterPath},
		"the CA's signer, attester leaf only":    {k.a.statusKey, k.a.statusPath, undecided, undecided, k.a.attesterPath[:1]},
		"the CA's signer, verified by key":       {k.a.statusKey, k.a.statusPath, undecided, undecided, nil},
		"a chain whose CA didn't issue the leaf": {k.b.statusKey, k.b.statusPath, undecided, undecided, []*x509.Certificate{k.a.attester, k.b.ca}},
	} {
		t.Run(name, func(t *testing.T) {
			srv := teststatuslist.ServeJWT(t)
			srv.Publish(t, tc.key, tc.chain, 0)
			a := k.a.attestation(srv, 0)
			a.SignerCertificates = tc.attestedBy
			p := policy(k, srv)
			tc.sameKey.check(t, p.Check(context.Background(), a, errRefused))
			p.ListSignerUnderAttesterCA = true
			tc.underCA.check(t, p.Check(context.Background(), a, errRefused))
		})
	}
}

func TestCheck_Undecided(t *testing.T) {
	k := newPKI(t)
	otherRoot, otherRootKey := testcert.CA(t, "outside the roots")
	untrusted, untrustedKey := testcert.Leaf(t, "signer outside the roots", otherRoot, otherRootKey)
	for name, publish := range map[string]func(srv *teststatuslist.JWTServer){
		"list unavailable":           func(*teststatuslist.JWTServer) {},
		"signer not in roots":        func(srv *teststatuslist.JWTServer) { srv.Publish(t, untrustedKey, []*x509.Certificate{untrusted}, 0) },
		"signer under a CA it isn't": func(srv *teststatuslist.JWTServer) { srv.Publish(t, k.b.attesterKey, k.b.attesterPath, 0) },
	} {
		t.Run(name, func(t *testing.T) {
			srv := teststatuslist.ServeJWT(t)
			publish(srv)
			undecided.check(t, policy(k, srv).Check(context.Background(), k.a.attestation(srv, 0), errRefused))
		})
	}
	t.Run("no signer key", func(t *testing.T) {
		srv := teststatuslist.ServeJWT(t)
		srv.Publish(t, k.a.attesterKey, k.a.attesterPath, 0)
		a := k.a.attestation(srv, 0)
		a.SignerKey = nil
		undecided.check(t, policy(k, srv).Check(context.Background(), a, errRefused))
	})
}

func TestCheck_StatusClaim(t *testing.T) {
	k := newPKI(t)
	srv := teststatuslist.ServeJWT(t)
	srv.Publish(t, k.a.attesterKey, k.a.attesterPath, 0)
	for name, tc := range map[string]struct {
		status        any
		hasStatus     bool
		require       bool
		want          outcome
		wantInMessage string
	}{
		"none":            {nil, false, false, valid, ""},
		"none, required":  {nil, false, true, refused, "no status claim"},
		"not an object":   {"revoked", true, false, refused, "not an object"},
		"null":            {nil, true, false, refused, "not an object"},
		"no status_list":  {map[string]any{"identifier_list": map[string]any{}}, true, false, refused, "status_list"},
		"negative idx":    {map[string]any{"status_list": map[string]any{"idx": -1.0, "uri": srv.URI}}, true, true, refused, "idx"},
		"no uri":          {map[string]any{"status_list": map[string]any{"idx": 0.0}}, true, false, refused, "uri"},
		"valid, required": {srv.Claim(0), true, true, valid, ""},
	} {
		t.Run(name, func(t *testing.T) {
			p := policy(k, srv)
			p.RequireStatus = tc.require
			a := k.a.attestation(srv, 0)
			a.Status, a.HasStatus = tc.status, tc.hasStatus
			err := p.Check(context.Background(), a, errRefused)
			tc.want.check(t, err)
			if tc.wantInMessage != "" && (err == nil || !strings.Contains(err.Error(), tc.wantInMessage)) {
				t.Errorf("err = %v, want it to mention %q", err, tc.wantInMessage)
			}
		})
	}
}

func TestCheck_Cache(t *testing.T) {
	k := newPKI(t)
	srv := teststatuslist.ServeJWT(t)
	srv.Publish(t, k.a.attesterKey, k.a.attesterPath, 0, uint8(statuslist.StatusInvalid))
	p := policy(k, srv)
	p.Checker.Cache = statuslist.NewCache(statuslist.CacheOptions{})
	valid.check(t, p.Check(context.Background(), k.a.attestation(srv, 0), errRefused))
	refused.check(t, p.Check(context.Background(), k.a.attestation(srv, 1), errRefused))
	if n := srv.Fetches.Load(); n != 1 {
		t.Errorf("fetched %d times, want once: the second check should use the cached list", n)
	}
	// The cached list is verified again, binding included.
	other := k.b.attestation(srv, 0)
	undecided.check(t, p.Check(context.Background(), other, errRefused))
}

func TestValidate(t *testing.T) {
	k := newPKI(t)
	production := statuslist.Checker{
		Roots: k.roots, Options: statuslist.VerifyOptions{Revocation: certrevocation.NoCheck{}},
		Cache: statuslist.NewCache(statuslist.CacheOptions{}),
	}
	for name, tc := range map[string]struct {
		mutate     func(c *statuslist.Checker)
		production bool
		want       string
	}{
		"production":               {func(*statuslist.Checker) {}, true, ""},
		"development, bare":        {func(c *statuslist.Checker) { *c = statuslist.Checker{Roots: k.roots} }, false, ""},
		"no roots":                 {func(c *statuslist.Checker) { c.Roots = nil }, false, "Roots"},
		"issuer key set":           {func(c *statuslist.Checker) { c.Options.IssuerKey = &k.a.attesterKey.PublicKey }, false, "IssuerKey"},
		"issuer set":               {func(c *statuslist.Checker) { c.Options.Issuer = "https://wallet-provider.example.com" }, false, "Issuer"},
		"unbound signer set":       {func(c *statuslist.Checker) { c.Options.UnboundSigner = statuslist.AnyListSigner }, false, "UnboundSigner"},
		"loopback fetcher":         {func(c *statuslist.Checker) { c.Fetcher.AllowLoopback = true }, true, "HardenedForProduction"},
		"unchecked transport":      {func(c *statuslist.Checker) { c.Fetcher.UncheckedTransport = true }, true, "HardenedForProduction"},
		"no revocation":            {func(c *statuslist.Checker) { c.Options.Revocation = nil }, true, "Revocation"},
		"no cache":                 {func(c *statuslist.Checker) { c.Cache = nil }, true, "Cache"},
		"invalid revocation":       {func(c *statuslist.Checker) { c.Options.Revocation = certrevocation.CRLs{} }, true, "Revocation"},
		"loopback, in development": {func(c *statuslist.Checker) { c.Fetcher.AllowLoopback = true }, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			c := production
			tc.mutate(&c)
			err := attestationstatus.Policy{Checker: c}.Validate(tc.production)
			switch {
			case tc.want == "" && err != nil:
				t.Errorf("Validate: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Errorf("Validate: %v, want an error naming %s", err, tc.want)
			}
		})
	}
}
