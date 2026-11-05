// Package walletprovider is the passport-vdc demo's Wallet Provider: one
// P-256 key and certificate, with which the library's Wallet Provider
// (oid4vcgo/walletprovider) signs Wallet Attestations, Key Attestations
// and its status list for the demo wallet. A real Wallet Provider
// attests a wallet instance only after checking platform evidence (key
// attestation, app integrity), and attests only keys held in secure
// hardware. This demo checks the Android Key Attestation chains the
// Android demo wallet sends with its keys, over challenges it issues,
// but vouches itself, with demo-only evidence the library is given in
// their place (DemoEvidenceKind), for a key sent without one (from iOS,
// or the CLI and web wallets), and, unless told otherwise, one whose
// chain isn't from hardware Google vouches for (an emulator's): see
// NewService. It runs as a service (NewService, cmd/wallet-provider)
// the wallets call through a Client, so they never hold its key.
//
// The key has a certificate from a demo Wallet Provider CA, carried as
// the x5c of every attestation it signs (HAIP 1.0 §4.4.1 for Wallet
// Attestations, §4.5.1 for Key Attestations: the trust anchor is left
// out of x5c, and the signing certificate isn't self-signed). The
// certificate names the provider's identifier, the attestations' "iss",
// as a URI subject alternative name, so the issuer can tell which
// Wallet Provider the CA certified it for. The issuer trusts the CA
// certificate for this provider alone (fapigo/server's
// AttesterIssuerBoundToAnchor).
package walletprovider

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/democert"
)

// Provider signs Wallet Attestations and Key Attestations.
type Provider struct {
	Issuer string // the provider's identifier, the attestations' "iss"
	Key    *ecdsa.PrivateKey

	// Certificate is Key's certificate, issued by CACertificate.
	Certificate *x509.Certificate
	// CACertificate is the demo Wallet Provider CA — the trust anchor
	// an issuer configures to accept this provider's Key Attestations.
	CACertificate *x509.Certificate
}

// New generates a Provider for issuer, an absolute URI: a fresh CA, a
// fresh key and the key's certificate, naming issuer. The CA's private
// key is discarded; nothing else is ever signed under it.
func New(issuer string) (*Provider, error) {
	issuerURI, err := url.Parse(issuer)
	if err != nil || !issuerURI.IsAbs() {
		return nil, fmt.Errorf("walletprovider: issuer %q isn't an absolute URI", issuer)
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: generate CA key: %w", err)
	}
	now := time.Now()
	caCert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo Wallet Provider CA", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageCertSign, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
	}, nil, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: generate key: %w", err)
	}
	cert, err := democert.Create(&x509.Certificate{
		Subject:   pkix.Name{CommonName: "passport-vdc demo Wallet Provider", Organization: []string{"IDFoundry demo"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature,
		URIs:     []*url.URL{issuerURI},
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &Provider{Issuer: issuer, Key: key, Certificate: cert, CACertificate: caCert}, nil
}

// Load restores a Provider from PEM as written by PEM: the private key,
// its certificate and the CA certificate. The certificate must name
// issuer.
func Load(issuer string, data []byte) (*Provider, error) {
	var key *ecdsa.PrivateKey
	var certs []*x509.Certificate
	for block, rest := pem.Decode(data); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "EC PRIVATE KEY":
			k, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("walletprovider: parse key: %w", err)
			}
			key = k
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("walletprovider: parse certificate: %w", err)
			}
			certs = append(certs, c)
		}
	}
	if key == nil {
		return nil, errors.New("walletprovider: no \"EC PRIVATE KEY\" PEM block")
	}
	if len(certs) != 2 {
		return nil, errors.New("walletprovider: want the key's certificate and the CA certificate — a file from before key attestation support has neither; delete it and rerun cmd/wallet-provider")
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("walletprovider: key must be P-256")
	}
	p := &Provider{Issuer: issuer, Key: key, Certificate: certs[0], CACertificate: certs[1]}
	if !key.PublicKey.Equal(p.Certificate.PublicKey) {
		return nil, errors.New("walletprovider: the certificate isn't for the key")
	}
	if err := p.Certificate.CheckSignatureFrom(p.CACertificate); err != nil {
		return nil, fmt.Errorf("walletprovider: the certificate isn't issued by the CA: %w", err)
	}
	if !slices.ContainsFunc(p.Certificate.URIs, func(u *url.URL) bool { return u.String() == issuer }) {
		return nil, fmt.Errorf("walletprovider: the certificate doesn't name Wallet Provider %q — a file from before issuer binding doesn't; delete it and rerun cmd/wallet-provider", issuer)
	}
	return p, nil
}

// PEM encodes the provider's private key, its certificate and the CA
// certificate. Treat the result as a secret: anyone holding it can
// attest wallets and keys this demo issuer will accept.
func (p *Provider) PEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(p.Key)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: marshal key: %w", err)
	}
	out := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Certificate.Raw})...)
	return append(out, p.CACertificatePEM()...), nil
}

// CACertificatePEM encodes the CA certificate — what an issuer trusts
// to accept this provider's Key Attestations.
func (p *Provider) CACertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CACertificate.Raw})
}
