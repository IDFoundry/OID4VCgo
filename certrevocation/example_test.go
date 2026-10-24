package certrevocation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
)

// A CA revokes a certificate it issued; CRLs, holding the CA's current
// list, refuses a chain through it. In a deployment the list comes from
// the CA's CRL distribution point, refreshed in the background (see
// CRLs.Lists), and the Checker goes in a resolver's Revocation field
// (verifier.X5ChainIssuerKeyResolver, verifier.X5CIssuerKeyResolver),
// which checks every verified path itself.
func ExampleCRLs() {
	now := time.Now()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Example IACA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	dsKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dsDER, _ := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "Example document signer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}, ca, &dsKey.PublicKey, caKey)
	ds, _ := x509.ParseCertificate(dsDER)

	// issue is the CA's CRL, revoking the serial numbers given.
	issue := func(revoked ...*big.Int) *x509.RevocationList {
		tmpl := &x509.RevocationList{Number: big.NewInt(now.Unix()), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
		for _, serial := range revoked {
			tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: now})
		}
		der, _ := x509.CreateRevocationList(rand.Reader, tmpl, ca, caKey)
		list, _ := x509.ParseRevocationList(der)
		return list
	}

	// current holds the list in memory; a refresher would replace it.
	var current atomic.Pointer[x509.RevocationList]
	current.Store(issue())
	checker := certrevocation.CRLs{Lists: func(context.Context) ([]*x509.RevocationList, error) {
		return []*x509.RevocationList{current.Load()}, nil
	}}
	check := certrevocation.Check{Chain: []*x509.Certificate{ds, ca}, Now: now}

	fmt.Println("before:", checker.CheckRevocation(context.Background(), check))
	current.Store(issue(ds.SerialNumber))
	err := checker.CheckRevocation(context.Background(), check)
	fmt.Println("after, revoked:", errors.Is(err, certrevocation.ErrRevoked))
	// Output:
	// before: <nil>
	// after, revoked: true
}
