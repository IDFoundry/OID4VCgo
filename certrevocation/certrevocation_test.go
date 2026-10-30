package certrevocation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/testcert"
)

// pki is a three-certificate chain, root → intermediate → leaf, and
// the keys that issue CRLs for it.
type pki struct {
	root, inter, leaf *x509.Certificate
	rootKey, interKey *ecdsa.PrivateKey
	chain             []*x509.Certificate
	otherCA           *x509.Certificate
	otherKey, fakeKey *ecdsa.PrivateKey
	fakeInter         *x509.Certificate
}

func newPKI(t *testing.T) pki {
	t.Helper()
	var p pki
	p.root, p.rootKey = testcert.CA(t, "root")
	p.inter, p.interKey = testcert.Intermediate(t, "intermediate", p.root, p.rootKey)
	p.leaf, _ = testcert.Leaf(t, "leaf", p.inter, p.interKey)
	p.chain = []*x509.Certificate{p.leaf, p.inter, p.root}
	p.otherCA, p.otherKey = testcert.CA(t, "another CA")
	// Another CA by the intermediate's own name, with another key: its
	// CRLs name the right issuer, but the intermediate never signed them.
	p.fakeInter, p.fakeKey = testcert.Intermediate(t, "intermediate", p.root, p.rootKey)
	return p
}

// withExtension is a CRL template carrying one critical extension.
func withExtension(t *testing.T, id asn1.ObjectIdentifier, value any) *x509.RevocationList {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.RevocationList{ExtraExtensions: []pkix.Extension{{Id: id, Critical: true, Value: der}}}
}

func TestCRLs(t *testing.T) {
	p := newPKI(t)
	now := time.Now()
	rootCRL := testcert.CRL(t, p.root, p.rootKey)
	interCRL := testcert.CRL(t, p.inter, p.interKey)
	tests := map[string]struct {
		lists []*x509.RevocationList
		want  error // nil, ErrRevoked or ErrNoCurrentCRL
	}{
		"good chain":           {[]*x509.RevocationList{interCRL, rootCRL}, nil},
		"nil list skipped":     {[]*x509.RevocationList{nil, interCRL, rootCRL}, nil},
		"revoked leaf":         {[]*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey, p.leaf.SerialNumber), rootCRL}, certrevocation.ErrRevoked},
		"revoked intermediate": {[]*x509.RevocationList{interCRL, testcert.CRL(t, p.root, p.rootKey, p.inter.SerialNumber)}, certrevocation.ErrRevoked},
		// The root's CRL revoking the root itself: the anchor is never
		// checked, and needs no CRL at all.
		"anchor never checked": {[]*x509.RevocationList{interCRL, testcert.CRL(t, p.root, p.rootKey, p.root.SerialNumber)}, nil},
		"stale CRL": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ThisUpdate: now.Add(-3 * time.Hour), NextUpdate: now.Add(-time.Hour),
		}, p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		"CRL not yet valid": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ThisUpdate: now.Add(time.Hour), NextUpdate: now.Add(2 * time.Hour),
		}, p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		// A stale CRL revoking the leaf beside a current one that
		// doesn't: only the current one counts.
		"stale revocation beside current list": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ThisUpdate: now.Add(-3 * time.Hour), NextUpdate: now.Add(-time.Hour),
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: p.leaf.SerialNumber, RevocationTime: now.Add(-2 * time.Hour)}},
		}, p.inter, p.interKey), interCRL, rootCRL}, nil},
		"wrong signer":      {[]*x509.RevocationList{testcert.CRL(t, p.fakeInter, p.fakeKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		"wrong issuer name": {[]*x509.RevocationList{testcert.CRL(t, p.otherCA, p.otherKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		"missing leaf CRL":  {[]*x509.RevocationList{rootCRL}, certrevocation.ErrNoCurrentCRL},
		"missing inter CRL": {[]*x509.RevocationList{interCRL}, certrevocation.ErrNoCurrentCRL},
		"no lists at all":   {nil, certrevocation.ErrNoCurrentCRL},
		"delta CRL ignored": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, withExtension(t, asn1.ObjectIdentifier{2, 5, 29, 27}, 1), p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		// An issuing distribution point extension (here an empty one)
		// may limit the list's scope: it isn't read as complete.
		"IDP-scoped CRL ignored": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, withExtension(t, asn1.ObjectIdentifier{2, 5, 29, 28}, asn1.RawValue{Tag: asn1.TagSequence, Class: asn1.ClassUniversal, IsCompound: true}), p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		// RFC 5280 §5.2 and §5.3: a CRL with a critical extension, or
		// critical entry extension, nobody processes MUST NOT be used.
		"unknown critical extension": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, withExtension(t, asn1.ObjectIdentifier{1, 2, 3, 4, 99}, true), p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		"unknown critical entry extension": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(7), RevocationTime: now.Add(-time.Hour), ExtraExtensions: withExtension(t, asn1.ObjectIdentifier{1, 2, 3, 4, 99}, true).ExtraExtensions}},
		}, p.inter, p.interKey), rootCRL}, certrevocation.ErrNoCurrentCRL},
		"unknown non-critical extension": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 99}, Value: []byte{0x05, 0x00}}},
		}, p.inter, p.interKey), rootCRL}, nil},
		// A CA whose clock runs a little fast: its fresh list is used.
		"thisUpdate within clock skew": {[]*x509.RevocationList{testcert.CRLFromTemplate(t, &x509.RevocationList{
			ThisUpdate: now.Add(certrevocation.CRLClockSkew - time.Minute), NextUpdate: now.Add(time.Hour),
		}, p.inter, p.interKey), rootCRL}, nil},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return tc.lists, nil }}
			err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain, Now: now})
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("CheckRevocation = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("CheckRevocation = %v, want %v", err, tc.want)
			}
			if errors.Is(err, certrevocation.ErrRevoked) && errors.Is(err, certrevocation.ErrNoCurrentCRL) {
				t.Errorf("%v is both revoked and undecided", err)
			}
		})
	}
}

func TestCRLs_ZeroNowIsCurrentTime(t *testing.T) {
	p := newPKI(t)
	lists := []*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey), testcert.CRL(t, p.root, p.rootKey)}
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return lists, nil }}
	if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain}); err != nil {
		t.Errorf("zero Now: %v", err)
	}
	if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain, Now: time.Now().Add(2 * time.Hour)}); !errors.Is(err, certrevocation.ErrNoCurrentCRL) {
		t.Errorf("past nextUpdate: %v, want ErrNoCurrentCRL", err)
	}
}

func TestCRLs_ListsError(t *testing.T) {
	p := newPKI(t)
	sentinel := errors.New("distribution point unreachable")
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return nil, sentinel }}
	err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain, Now: time.Now()})
	if !errors.Is(err, sentinel) {
		t.Errorf("CheckRevocation = %v, want it to wrap the Lists error", err)
	}
}

func TestCRLs_Validate(t *testing.T) {
	if err := (certrevocation.CRLs{}).Validate(); err == nil {
		t.Error("Validate with no Lists: nil")
	}
	if err := (certrevocation.CRLs{}).CheckRevocation(context.Background(), certrevocation.Check{}); err == nil {
		t.Error("CheckRevocation with no Lists: nil")
	}
	ok := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return nil, nil }}
	if err := ok.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestNoCheck(t *testing.T) {
	p := newPKI(t)
	var checker certrevocation.Checker = certrevocation.NoCheck{}
	if err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: p.chain}); err != nil {
		t.Errorf("NoCheck: %v", err)
	}
}

// A chain ending at a certificate that isn't self-signed — a pinned
// leaf, or an intermediate among the roots — is checked against its
// CA's CRL too, verified with the CA's certificate from Issuers; a
// self-signed anchor has nothing to check. Otherwise a root's
// revocation of an intermediate placed in the roots beside it would
// never be asked: x509 verifies the path ending at the intermediate.
func TestCRLs_AnchorNotSelfSigned(t *testing.T) {
	p := newPKI(t)
	pinned := []*x509.Certificate{p.leaf}
	toInter := []*x509.Certificate{p.leaf, p.inter}
	interCRL := testcert.CRL(t, p.inter, p.interKey)
	tests := map[string]struct {
		lists   []*x509.RevocationList
		issuers []*x509.Certificate
		chain   []*x509.Certificate
		want    error
	}{
		"clean":         {[]*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey)}, []*x509.Certificate{p.root, p.inter}, pinned, nil},
		"revoked":       {[]*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey, p.leaf.SerialNumber)}, []*x509.Certificate{p.inter}, pinned, certrevocation.ErrRevoked},
		"no lists":      {nil, []*x509.Certificate{p.inter}, pinned, certrevocation.ErrNoCurrentCRL},
		"no issuers":    {[]*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey)}, nil, pinned, certrevocation.ErrNoCurrentCRL},
		"forged issuer": {[]*x509.RevocationList{testcert.CRL(t, p.fakeInter, p.fakeKey)}, []*x509.Certificate{nil, p.fakeInter}, pinned, certrevocation.ErrNoCurrentCRL},
		"self-signed":   {nil, nil, []*x509.Certificate{p.root}, nil},

		// An intermediate among the roots, the anchor of [leaf, inter].
		"intermediate anchor, clean":               {[]*x509.RevocationList{interCRL, testcert.CRL(t, p.root, p.rootKey)}, []*x509.Certificate{p.root}, toInter, nil},
		"intermediate anchor, revoked by its root": {[]*x509.RevocationList{interCRL, testcert.CRL(t, p.root, p.rootKey, p.inter.SerialNumber)}, []*x509.Certificate{p.root}, toInter, certrevocation.ErrRevoked},
		"intermediate anchor, no root CRL":         {[]*x509.RevocationList{interCRL}, []*x509.Certificate{p.root}, toInter, certrevocation.ErrNoCurrentCRL},
		"intermediate anchor, root not given":      {[]*x509.RevocationList{interCRL, testcert.CRL(t, p.root, p.rootKey)}, nil, toInter, certrevocation.ErrNoCurrentCRL},
		// The leaf is still checked first: its revocation is reported
		// as such, whatever the anchor's.
		"intermediate anchor, revoked leaf": {[]*x509.RevocationList{testcert.CRL(t, p.inter, p.interKey, p.leaf.SerialNumber)}, nil, toInter, certrevocation.ErrRevoked},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) { return tc.lists, nil }, Issuers: tc.issuers}
			err := checker.CheckRevocation(context.Background(), certrevocation.Check{Chain: tc.chain})
			switch {
			case tc.want == nil && err != nil:
				t.Fatalf("CheckRevocation = %v, want nil", err)
			case tc.want != nil && !errors.Is(err, tc.want):
				t.Fatalf("CheckRevocation = %v, want %v", err, tc.want)
			}
		})
	}
}
