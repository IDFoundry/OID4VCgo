package certchain

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// crls is a certrevocation.CRLs over a fixed set of lists.
func crls(lists ...*x509.RevocationList) certrevocation.CRLs {
	return certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return lists, nil }}
}

// crossCertified is a leaf under an intermediate both rootA and rootB
// certify, as interA and interB: two verified paths.
type crossCertified struct {
	rootA, rootB, interA, interB, leaf *x509.Certificate
	rootAKey, rootBKey, interKey       *ecdsa.PrivateKey
	roots                              *x509.CertPool
	ders                               [][]byte
}

func newCrossCertified(t *testing.T) crossCertified {
	t.Helper()
	var c crossCertified
	c.rootA, c.rootAKey = testcert.CA(t, "root A")
	c.rootB, c.rootBKey = testcert.CA(t, "root B")
	c.interA, c.interKey = testcert.Intermediate(t, "intermediate", c.rootA, c.rootAKey)
	c.interB = testcert.CrossCertify(t, c.interA, c.rootB, c.rootBKey)
	c.leaf, _ = testcert.Leaf(t, "leaf", c.interA, c.interKey)
	c.roots = x509.NewCertPool()
	c.roots.AddCert(c.rootA)
	c.roots.AddCert(c.rootB)
	c.ders = [][]byte{c.leaf.Raw, c.interA.Raw, c.interB.Raw}
	return c
}

// Through an intermediate certified by two roots, a leaf has two
// verified paths. Revoking the intermediate's certificate under one
// root leaves the other path, which alone is returned; revoking both
// leaves none.
func TestVerifyTrustedChainsAt_Revocation(t *testing.T) {
	c := newCrossCertified(t)
	rootA, rootB, interA, interB, leaf := c.rootA, c.rootB, c.interA, c.interB, c.leaf
	rootAKey, rootBKey, interKey, roots := c.rootAKey, c.rootBKey, c.interKey, c.roots
	ders := c.ders
	ctx := context.Background()

	leafCRL := testcert.CRL(t, interA, interKey)
	cleanA, cleanB := testcert.CRL(t, rootA, rootAKey), testcert.CRL(t, rootB, rootBKey)
	revokedA := testcert.CRL(t, rootA, rootAKey, interA.SerialNumber)
	revokedB := testcert.CRL(t, rootB, rootBKey, interB.SerialNumber)

	if _, chains, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, nil, time.Time{}); err != nil || len(chains) != 2 {
		t.Fatalf("no revocation check: %d paths, %v; want both", len(chains), err)
	}
	if _, chains, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(leafCRL, cleanA, cleanB), time.Time{}); err != nil || len(chains) != 2 {
		t.Fatalf("clean CRLs: %d paths, %v; want both", len(chains), err)
	}

	_, chains, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(leafCRL, revokedA, cleanB), time.Time{})
	if err != nil {
		t.Fatalf("one path revoked: %v", err)
	}
	if len(chains) != 1 || !chains[0][len(chains[0])-1].Equal(rootB) {
		t.Errorf("one path revoked: got %d paths; want only the one to root B", len(chains))
	}

	if _, _, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(leafCRL, revokedA, revokedB), time.Time{}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("every path revoked: %v, want ErrRevoked", err)
	}
	revokedLeaf := testcert.CRL(t, interA, interKey, leaf.SerialNumber)
	if _, _, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(revokedLeaf, cleanA, cleanB), time.Time{}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("revoked leaf: %v, want ErrRevoked", err)
	}
	if _, _, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(leafCRL), time.Time{}); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Errorf("no CRL from either root: %v, want ErrNoCurrentCRL", err)
	}
}

// Revocation narrows the paths the policy approved, not every verified
// path: a clean path the policy refused doesn't rescue a revoked one it
// approved.
func TestVerifyTrustedChainsAt_PolicyThenRevocation(t *testing.T) {
	c := newCrossCertified(t)
	rootA, rootB, interA := c.rootA, c.rootB, c.interA
	rootAKey, rootBKey, interKey, roots := c.rootAKey, c.rootBKey, c.interKey, c.roots
	onlyRootA := func(_ *x509.Certificate, chains [][]*x509.Certificate) error {
		for _, chain := range chains {
			if chain[len(chain)-1].Equal(rootA) {
				return nil
			}
		}
		return errors.New("not under root A")
	}
	revocation := crls(testcert.CRL(t, interA, interKey), testcert.CRL(t, rootA, rootAKey, interA.SerialNumber), testcert.CRL(t, rootB, rootBKey))
	if _, _, err := VerifyTrustedChainsAt(context.Background(), c.ders, roots, onlyRootA, revocation, time.Time{}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("approved path revoked, other path refused by policy: %v, want ErrRevoked", err)
	}
}
