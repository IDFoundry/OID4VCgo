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

// A leaf pinned in the roots verifies as the path [leaf] alone. It's
// still checked, against a CRL from the CA it names as its issuer,
// whose certificate CRLs.Issuers supplies to verify that CRL with;
// without it, or without a current CRL from it, the leaf is refused.
func TestVerifyTrustedChainsAt_PinnedLeaf(t *testing.T) {
	ca, caKey := testcert.CA(t, "CA")
	leaf, _ := testcert.Leaf(t, "pinned issuer", ca, caKey)
	impostor, impostorKey := testcert.CA(t, "CA")
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	issuedBy := func(issuer *x509.Certificate, lists ...*x509.RevocationList) certrevocation.CRLs {
		c := crls(lists...)
		c.Issuers = []*x509.Certificate{issuer}
		return c
	}
	tests := map[string]struct {
		der        []byte
		revocation certrevocation.Checker
		want       error
	}{
		"clean CRL":           {leaf.Raw, issuedBy(ca, testcert.CRL(t, ca, caKey)), nil},
		"revoked":             {leaf.Raw, issuedBy(ca, testcert.CRL(t, ca, caKey, leaf.SerialNumber)), certrevocation.ErrRevoked},
		"no CRL":              {leaf.Raw, issuedBy(ca), certrevocation.ErrNoCurrentCRL},
		"issuer not given":    {leaf.Raw, crls(testcert.CRL(t, ca, caKey)), certrevocation.ErrNoCurrentCRL},
		"same-named impostor": {leaf.Raw, issuedBy(impostor, testcert.CRL(t, impostor, impostorKey)), certrevocation.ErrNoCurrentCRL},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, chains, err := VerifyTrustedChainsAt(context.Background(), [][]byte{tc.der}, roots, nil, tc.revocation, time.Time{})
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("err = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if len(chains) != 1 || len(chains[0]) != 1 {
				t.Fatalf("got %d paths, want the one-certificate path alone", len(chains))
			}
		})
	}
}

// When no path passes, the error says the chain is revoked only if
// every path was refused as revoked: with one path revoked and the
// other undecided (no CRL from its root), it's undecided, since that
// path may pass once its CRL is available, and doesn't wrap ErrRevoked.
func TestNotRevokedChains_RevokedOnlyWhenEveryPathIs(t *testing.T) {
	c := newCrossCertified(t)
	leafCRL := testcert.CRL(t, c.interA, c.interKey)
	revokedA := testcert.CRL(t, c.rootA, c.rootAKey, c.interA.SerialNumber)
	revokedB := testcert.CRL(t, c.rootB, c.rootBKey, c.interB.SerialNumber)
	ctx := context.Background()

	_, _, err := VerifyTrustedChainsAt(ctx, c.ders, c.roots, nil, crls(leafCRL, revokedA), time.Time{})
	if !errors.Is(err, ErrRevocationUndecided) || !errors.Is(err, certrevocation.ErrNoCurrentCRL) || errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("one path revoked, the other undecided: %v, want ErrRevocationUndecided and ErrNoCurrentCRL, not ErrRevoked", err)
	}
	_, _, err = VerifyTrustedChainsAt(ctx, c.ders, c.roots, nil, crls(leafCRL, revokedA, revokedB), time.Time{})
	if !errors.Is(err, certrevocation.ErrRevoked) || errors.Is(err, ErrRevocationUndecided) {
		t.Errorf("every path revoked: %v, want ErrRevoked alone", err)
	}
	if _, err := NotRevokedChains(ctx, nil, crls(), time.Time{}); err == nil || errors.Is(err, certrevocation.ErrRevoked) || errors.Is(err, ErrRevocationUndecided) {
		t.Errorf("no paths: %v, want a plain error", err)
	}
}

// A pool holding an intermediate beside its root (a whole chain bundle
// loaded as the roots) verifies two paths, [leaf, intermediate, root]
// and [leaf, intermediate]. The root's revocation of the intermediate
// refuses the first; the second is refused too, since its anchor isn't
// self-signed and is checked against the root's CRL, rather than
// keeping a leaf the revoked CA issued.
func TestVerifyTrustedChainsAt_RevokedIntermediateInRoots(t *testing.T) {
	root, rootKey := testcert.CA(t, "root")
	inter, interKey := testcert.Intermediate(t, "issuing CA", root, rootKey)
	leaf, _ := testcert.Leaf(t, "leaf", inter, interKey)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	roots.AddCert(inter)
	ders := [][]byte{leaf.Raw, inter.Raw}
	withRoot := func(lists ...*x509.RevocationList) certrevocation.CRLs {
		c := crls(lists...)
		c.Issuers = []*x509.Certificate{root}
		return c
	}
	interCRL := testcert.CRL(t, inter, interKey)
	revoking := testcert.CRL(t, root, rootKey, inter.SerialNumber)
	ctx := context.Background()

	if _, _, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, withRoot(interCRL, revoking), time.Time{}); !errors.Is(err, certrevocation.ErrRevoked) {
		t.Errorf("intermediate revoked, root among Issuers: %v, want ErrRevoked", err)
	}
	if _, _, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, crls(interCRL, revoking), time.Time{}); err == nil {
		t.Error("intermediate revoked, root not among Issuers: accepted")
	}
	_, chains, err := VerifyTrustedChainsAt(ctx, ders, roots, nil, withRoot(interCRL, testcert.CRL(t, root, rootKey)), time.Time{})
	if err != nil || len(chains) != 2 {
		t.Errorf("clean CRLs: %d paths, %v; want both", len(chains), err)
	}
}
