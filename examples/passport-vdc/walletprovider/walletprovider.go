// Package walletprovider is the passport-vdc demo's stand-in Wallet
// Provider: one P-256 key that signs Wallet Attestations and Key
// Attestations for the demo wallet. A real Wallet Provider would attest
// a wallet instance only after checking platform evidence (key
// attestation, app integrity), and would attest only keys held in
// secure hardware; this demo attests any key it's given.
//
// The key has a certificate from a demo Wallet Provider CA, carried as
// each Key Attestation's x5c (HAIP 1.0 §4.5.1: the signing certificate
// must not be self-signed, and the trust anchor is left out of x5c).
// The issuer trusts the CA certificate. Wallet Attestations still name
// the key by kid, since fapigo/server resolves the attester key from
// the client's registered JWK Set.
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

// KeyID is the "kid" of the provider's one key.
const KeyID = "demo-wallet-provider-1"

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

// PublicJWKS returns the provider's public key as a JWK Set — what the
// issuer registers to verify this provider's Wallet Attestations.
func (p *Provider) PublicJWKS() ([]byte, error) {
	jwk, err := ecJWK(&p.Key.PublicKey)
	if err != nil {
		return nil, err
	}
	jwk["kid"], jwk["alg"], jwk["use"] = KeyID, "ES256", "sig"
	return json.Marshal(map[string]any{"keys": []map[string]string{jwk}})
}

// Attest issues a Wallet Attestation binding instanceKey to clientID,
// valid for lifetime from now.
func (p *Provider) Attest(clientID string, instanceKey crypto.PublicKey, now time.Time, lifetime time.Duration) (string, error) {
	return attestation.IssueWalletAttestation(p.Key, oid4vci.ES256, attestation.Header{KeyID: KeyID}, attestation.WalletAttestationClaims{
		Issuer: p.Issuer, Subject: clientID, InstanceKey: instanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(lifetime).Unix(),
		Extra: attestation.WalletAttestationExtraClaims{WalletName: "passport-vdc demo wallet"},
	})
}

// KeyAttestationHeader is the JOSE header conveyance for a Key
// Attestation: x5c holding the provider's certificate, without the CA.
func (p *Provider) KeyAttestationHeader() attestation.Header {
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
		jwk, err := ecJWK(k)
		if err != nil {
			return attestation.Claims{}, err
		}
		raw, err := json.Marshal(jwk)
		if err != nil {
			return attestation.Claims{}, fmt.Errorf("walletprovider: marshal key: %w", err)
		}
		attested = append(attested, raw)
	}
	exp := now.Add(lifetime).Unix()
	return attestation.Claims{Issuer: p.Issuer, ExpiresAt: &exp, AttestedKeys: attested}, nil
}

// ecJWK encodes a P-256 public key as JWK members.
func ecJWK(pub *ecdsa.PublicKey) (map[string]string, error) {
	raw, err := pub.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		return nil, fmt.Errorf("walletprovider: encode public key: %w", err)
	}
	size := (len(raw) - 1) / 2
	b64 := base64.RawURLEncoding
	return map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": b64.EncodeToString(raw[1 : 1+size]), "y": b64.EncodeToString(raw[1+size:]),
	}, nil
}
