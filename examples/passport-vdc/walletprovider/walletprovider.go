// Package walletprovider is the passport-vdc demo's stand-in Wallet
// Provider: one P-256 key that signs Wallet Attestations and Key
// Attestations for the demo wallet. A real Wallet Provider would attest
// a wallet instance only after checking platform evidence (key
// attestation, app integrity), and would attest only keys held in
// secure hardware; this demo attests any key it's given.
//
// The key has a certificate from a demo Wallet Provider CA, carried as
// the x5c of every attestation it signs (HAIP 1.0 §4.4.1 for Wallet
// Attestations, §4.5.1 for Key Attestations: the trust anchor is left
// out of x5c, and the signing certificate isn't self-signed). The
// issuer trusts the CA certificate.
package walletprovider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
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

// New generates a Provider: a fresh CA, a fresh key and the key's
// certificate. The CA's private key is discarded; nothing else is ever
// signed under it.
func New(issuer string) (*Provider, error) {
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
	}, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	return &Provider{Issuer: issuer, Key: key, Certificate: cert, CACertificate: caCert}, nil
}

// Load restores a Provider from PEM as written by PEM: the private key,
// its certificate and the CA certificate.
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

// Attest issues a Wallet Attestation binding instanceKey to clientID,
// valid for lifetime from now, carrying the provider's certificate as
// x5c (HAIP 1.0 §4.4.1).
func (p *Provider) Attest(clientID string, instanceKey crypto.PublicKey, now time.Time, lifetime time.Duration) (string, error) {
	return attestation.IssueWalletAttestation(p.Key, oid4vci.ES256, p.x5cHeader(), attestation.WalletAttestationClaims{
		Issuer: p.Issuer, Subject: clientID, InstanceKey: instanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(lifetime).Unix(),
		Extra: attestation.WalletAttestationExtraClaims{WalletName: "passport-vdc demo wallet"},
	})
}

// KeyAttestationHeader is the JOSE header conveyance for a Key
// Attestation: x5c holding the provider's certificate, without the CA.
func (p *Provider) KeyAttestationHeader() attestation.Header { return p.x5cHeader() }

// x5cHeader conveys the provider's key by its certificate alone, the
// trust anchor left out.
func (p *Provider) x5cHeader() attestation.Header {
	return attestation.Header{X5C: []string{base64.StdEncoding.EncodeToString(p.Certificate.Raw)}}
}

// KeyAttestationClaims returns the claims of a Key Attestation over
// keys, expiring lifetime after now. The signer (wallet.Wallet's
// GenerateAttestationProof) sets iat and the issuer's nonce. It asserts
// no key_storage or user_authentication level: the demo's holder keys
// are ordinary software keys.
func (p *Provider) KeyAttestationClaims(keys []*ecdsa.PublicKey, now time.Time, lifetime time.Duration) (attestation.Claims, error) {
	attested := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		raw, err := attestation.AttestedKey(k)
		if err != nil {
			return attestation.Claims{}, fmt.Errorf("walletprovider: %w", err)
		}
		attested = append(attested, raw)
	}
	exp := now.Add(lifetime).Unix()
	return attestation.Claims{Issuer: p.Issuer, ExpiresAt: &exp, AttestedKeys: attested}, nil
}
