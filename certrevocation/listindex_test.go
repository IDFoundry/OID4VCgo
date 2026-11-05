package certrevocation_test

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// The same parsed lists checked again and again, as a Refresher's are,
// give each check the answer a first check of them would: a list
// verified under one issuer is still refused for another of the same
// name, a revoked serial is still found, and the times are still
// checked at each check's Now.
func TestCRLs_ListsCheckedAgain(t *testing.T) {
	p := newPKI(t)
	now := time.Now()
	interCRL := testcert.CRL(t, p.inter, p.interKey, big.NewInt(99), p.leaf.SerialNumber)
	rootCRL := testcert.CRL(t, p.root, p.rootKey)
	lists := []*x509.RevocationList{interCRL, rootCRL}
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return lists, nil }}
	fakeLeaf, _ := testcert.Leaf(t, "leaf", p.fakeInter, p.fakeKey)
	// Another leaf of the intermediate's, by a serial its list doesn't
	// name.
	otherLeaf, _ := testcert.Issue(t, &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "other leaf"}}, p.inter, p.interKey)
	for range 3 {
		if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain, Now: now}); !errors.Is(err, certrevocation.ErrRevoked) {
			t.Fatalf("revoked leaf: %v, want ErrRevoked", err)
		}
		if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{otherLeaf, p.inter, p.root}, Now: now}); err != nil {
			t.Fatalf("good leaf: %v", err)
		}
		// The intermediate's list names the fake intermediate's issuer
		// name, but the fake's key never signed it.
		if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{fakeLeaf, p.fakeInter, p.root}, Now: now}); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
			t.Fatalf("list under another key of the same name: %v, want ErrNoCurrentCRL", err)
		}
		if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: []*x509.Certificate{otherLeaf, p.inter, p.root}, Now: now.Add(2 * time.Hour)}); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
			t.Fatalf("after nextUpdate: %v, want ErrNoCurrentCRL", err)
		}
	}
}

// What the package keeps about a list or anchor goes once nothing
// holds it.
func TestCRLs_IndexDroppedWithList(t *testing.T) {
	p := newPKI(t)
	// The lists earlier tests left go first, so the count is this
	// test's alone.
	indexed := func() int { n, _ := certrevocation.IndexedForTest(); return n }
	collected := func(want int) bool {
		for range 50 {
			runtime.GC()
			if indexed() == want {
				return true
			}
			time.Sleep(10 * time.Millisecond)
		}
		return false
	}
	if !collected(0) {
		t.Skipf("%d lists from earlier tests still indexed", indexed())
	}
	func() {
		lists := []*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey), testcert.CRL(t, p.root, p.rootKey)}
		checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return lists, nil }}
		if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain}); err != nil {
			t.Fatal(err)
		}
		if n, _ := certrevocation.IndexedForTest(); n != 2 {
			t.Fatalf("%d lists indexed, want 2", n)
		}
	}()
	if !collected(0) {
		t.Fatalf("%d lists still indexed after they became unreachable, want 0", indexed())
	}
}

// Issuer certificates without their DER, built by hand, aren't told
// apart by it: one whose key signed a list doesn't vouch for another's.
func TestCRLs_HandBuiltIssuersNotConfused(t *testing.T) {
	p := newPKI(t)
	list := testcert.CRL(t, p.inter, p.interKey)
	signer := &x509.Certificate{PublicKey: p.inter.PublicKey, PublicKeyAlgorithm: p.inter.PublicKeyAlgorithm, Subject: p.inter.Subject}
	other := &x509.Certificate{PublicKey: p.fakeInter.PublicKey, PublicKeyAlgorithm: p.fakeInter.PublicKeyAlgorithm, Subject: p.fakeInter.Subject}
	if !certrevocation.SignedByForTest(list, signer) {
		t.Fatal("the list's own issuer, by hand: not signed")
	}
	if certrevocation.SignedByForTest(list, other) {
		t.Error("another key, by hand: signed, from the first issuer's answer")
	}
}
