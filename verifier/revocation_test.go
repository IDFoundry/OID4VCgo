package verifier_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
	"github.com/idfoundry/oid4vcgo/storage"
	"github.com/idfoundry/oid4vcgo/verifier"
)

// revocationFixture is an issuer CA, its trust anchor pool, and an
// issuer (document signer) certificate under it.
type revocationFixture struct {
	ca    *x509.Certificate
	caKey *ecdsa.PrivateKey
	roots *x509.CertPool
	leaf  *x509.Certificate
}

func newRevocationFixture(t *testing.T) revocationFixture {
	t.Helper()
	var f revocationFixture
	f.ca, f.caKey = testcert.CA(t, "issuer CA")
	f.roots = x509.NewCertPool()
	f.roots.AddCert(f.ca)
	f.leaf, _ = testcert.Leaf(t, "issuer", f.ca, f.caKey)
	return f
}

// crls is a certrevocation.CRLs holding the CA's CRL, revoking the
// certificates given.
func (f revocationFixture) crls(t *testing.T, revoked ...*x509.Certificate) certrevocation.CRLs {
	t.Helper()
	serials := make([]*big.Int, 0, len(revoked))
	for _, cert := range revoked {
		serials = append(serials, cert.SerialNumber)
	}
	list := testcert.CRL(t, f.ca, f.caKey, serials...)
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return []*x509.RevocationList{list}, nil
	}}
}

var anyLeaf = func(*x509.Certificate, [][]*x509.Certificate) error { return nil }

// resolveBoth runs both of a resolver's paths — the key, and the issuer
// chains — for the leaf, through X5CIssuerKeyResolver ("x5c") or
// X5ChainIssuerKeyResolver ("x5chain"), with revocation, returning the
// key path's error and the chain path's.
func resolveBoth(f revocationFixture, kind string, revocation certrevocation.Checker) (keyErr, chainErr error) {
	ctx := context.Background()
	if kind == "x5c" {
		r := verifier.X5CIssuerKeyResolver{Roots: f.roots, LeafPolicy: anyLeaf, Revocation: revocation}
		_, _, keyErr = r.ResolveIssuerKey(ctx, x5cHeader(f.leaf), nil)
		_, chainErr = r.ResolveIssuerChains(ctx, x5cHeader(f.leaf))
		return keyErr, chainErr
	}
	r := verifier.X5ChainIssuerKeyResolver{Roots: f.roots, LeafPolicy: anyLeaf, Revocation: revocation}
	_, _, keyErr = r.ResolveMdocIssuerKey(ctx, x5chainOf(f.leaf), "org.iso.18013.5.1.mDL")
	_, chainErr = r.ResolveMdocIssuerChains(ctx, x5chainOf(f.leaf), "org.iso.18013.5.1.mDL")
	return keyErr, chainErr
}

// Both X.509 resolvers check revocation on both of their paths: a
// revoked issuer certificate is refused with ErrRevoked, one with no
// current CRL fails closed, and a clean CRL accepts.
func TestX5CResolvers_Revocation(t *testing.T) {
	f := newRevocationFixture(t)
	stale := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return []*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ThisUpdate: time.Now().Add(-3 * time.Hour), NextUpdate: time.Now().Add(-time.Hour),
		}, f.ca, f.caKey)}, nil
	}}
	for _, kind := range []string{"x5c", "x5chain"} {
		t.Run(kind, func(t *testing.T) {
			if keyErr, chainErr := resolveBoth(f, kind, f.crls(t)); keyErr != nil || chainErr != nil {
				t.Errorf("clean CRL: %v, %v", keyErr, chainErr)
			}
			keyErr, chainErr := resolveBoth(f, kind, f.crls(t, f.leaf))
			if !errors.Is(keyErr, certrevocation.ErrRevoked) || !errors.Is(chainErr, certrevocation.ErrRevoked) {
				t.Errorf("revoked issuer: %v, %v; want ErrRevoked", keyErr, chainErr)
			}
			keyErr, chainErr = resolveBoth(f, kind, stale)
			if !errors.Is(keyErr, certrevocation.ErrNoCurrentCRL) || !errors.Is(chainErr, certrevocation.ErrNoCurrentCRL) {
				t.Errorf("stale CRL: %v, %v; want ErrNoCurrentCRL", keyErr, chainErr)
			}
			for name, revocation := range map[string]certrevocation.Checker{"nil": nil, "CRLs without Lists": certrevocation.CRLs{}} {
				keyErr, chainErr := resolveBoth(f, kind, revocation)
				if keyErr == nil || chainErr == nil || !strings.Contains(keyErr.Error(), "Revocation") {
					t.Errorf("%s Revocation: %v, %v; want refused", name, keyErr, chainErr)
				}
			}
		})
	}
	if err := (verifier.X5CIssuerKeyResolver{Revocation: certrevocation.NoCheck{}}).Validate(); err != nil {
		t.Errorf("X5CIssuerKeyResolver with NoCheck: %v", err)
	}
	if err := (verifier.X5ChainIssuerKeyResolver{}).Validate(); err == nil {
		t.Error("X5ChainIssuerKeyResolver without Revocation: valid")
	}
}

// A resolver without Revocation is refused when it's configured, before
// any credential reaches it: by VerifyResponse, and by NewTransactions.
func TestRevocationRequiredAtConfiguration(t *testing.T) {
	v := newTestVerifier(t)
	roots := x509.NewCertPool()
	for name, req := range map[string]verifier.VerifyResponseRequest{
		"issuer_keys":      {IssuerKeys: verifier.X5CIssuerKeyResolver{Roots: roots}},
		"mdoc_issuer_keys": {MdocIssuerKeys: verifier.X5ChainIssuerKeyResolver{Roots: roots}},
	} {
		req.MaxKeyBindingAge = time.Hour
		if _, err := verifier.NewTransactions(v, storage.NewVerifierTransactionStore(), verifier.TransactionsConfig{RequestURIBase: txBase, Verify: req}); err == nil || !strings.Contains(err.Error(), "Revocation is required") {
			t.Errorf("NewTransactions, %s: %v; want Revocation required", name, err)
		}
		req.Query, req.ExpectedNonce = testIdentityQuery(t), "nonce"
		if _, err := v.VerifyResponse(context.Background(), req); err == nil || !strings.Contains(err.Error(), "Revocation is required") {
			t.Errorf("VerifyResponse, %s: %v; want Revocation required", name, err)
		}
	}
}

// An issuing CA placed in the roots beside the root that revoked it is
// still refused: the path ending at it is checked against the root's
// CRL, the root's certificate coming from CRLs.Issuers.
func TestX5CResolvers_RevokedIntermediateInRoots(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	var f revocationFixture
	f.ca, f.caKey = testcert.Intermediate(t, "issuer CA", root, rootKey)
	f.leaf, _ = testcert.Leaf(t, "issuer", f.ca, f.caKey)
	f.roots = x509.NewCertPool()
	f.roots.AddCert(root)
	f.roots.AddCert(f.ca)
	lists := []*x509.RevocationList{testcert.CRL(t, f.ca, f.caKey), testcert.CRL(t, root, rootKey, f.ca.SerialNumber)}
	revocation := certrevocation.CRLs{
		Lists:   func(context.Context) ([]*x509.RevocationList, error) { return lists, nil },
		Issuers: []*x509.Certificate{root},
	}
	for _, kind := range []string{"x5c", "x5chain"} {
		keyErr, chainErr := resolveBoth(f, kind, revocation)
		if !errors.Is(keyErr, certrevocation.ErrRevoked) || !errors.Is(chainErr, certrevocation.ErrRevoked) {
			t.Errorf("%s: %v, %v; want ErrRevoked", kind, keyErr, chainErr)
		}
	}
}
