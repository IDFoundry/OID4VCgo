package conformancecrl

import (
	"crypto/ecdsa"
	"fmt"
	"net"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// Fixture is a CA publishing, on a loopback port, a CRL that revokes
// one of its two leaves: for the harnesses' tests of what a Trust's
// checker accepts and refuses. Publisher isn't started; Trust checks
// against it once it is.
type Fixture struct {
	CA                  *Authority
	GoodKey, RevokedKey *ecdsa.PrivateKey
	Good, Revoked       Leaf
	Publisher           Publisher
	Trust               Trust
}

// NewFixture builds a Fixture whose CA is named name, its distribution
// point on a free localhost port.
func NewFixture(name string) (*Fixture, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if err := ln.Close(); err != nil {
		return nil, err
	}
	ca, err := NewAuthority(name, URL(net.JoinHostPort("localhost", port), name))
	if err != nil {
		return nil, err
	}
	f := &Fixture{CA: ca}
	if f.GoodKey, f.Good, err = ca.IssueKey(name+"-good", nil); err != nil {
		return nil, err
	}
	if f.RevokedKey, f.Revoked, err = ca.IssueKey(name+"-revoked", nil); err != nil {
		return nil, err
	}
	crl, err := ca.CRL(f.Revoked.Cert)
	if err != nil {
		return nil, err
	}
	tlsCertPEM, tlsKeyPEM, err := conformancecert.SelfSignedPEM("localhost", []string{"localhost"})
	if err != nil {
		return nil, fmt.Errorf("conformancecrl: fixture tls certificate: %w", err)
	}
	f.Publisher = Publisher{
		ListenAddr: net.JoinHostPort("127.0.0.1", port), TLSCertificatePEM: tlsCertPEM, TLSPrivateKeyPEM: tlsKeyPEM,
		CRLs: map[string]string{ca.Path(): crl},
	}
	f.Trust = Trust{DistributionPoints: []DistributionPoint{ca.DistributionPoint()}, TLSTrustAnchorsPEM: tlsCertPEM}
	return f, nil
}
