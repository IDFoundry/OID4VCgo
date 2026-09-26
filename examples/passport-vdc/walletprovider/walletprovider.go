// Package walletprovider is the passport-vdc demo's stand-in Wallet
// Provider: one P-256 key that signs Wallet Attestations for the demo
// wallet. A real Wallet Provider would attest a wallet instance only
// after checking platform evidence (key attestation, app integrity);
// this demo attests any instance key it's given.
package walletprovider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
)

// KeyID is the "kid" of the provider's one key.
const KeyID = "demo-wallet-provider-1"

// Provider signs Wallet Attestations.
type Provider struct {
	Issuer string // the provider's identifier, the attestation "iss"
	Key    *ecdsa.PrivateKey
}

// New generates a Provider with a fresh key.
func New(issuer string) (*Provider, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: generate key: %w", err)
	}
	return &Provider{Issuer: issuer, Key: key}, nil
}

// Load restores a Provider from a PEM-encoded EC private key, as
// written by PrivateKeyPEM.
func Load(issuer string, keyPEM []byte) (*Provider, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("walletprovider: expected an \"EC PRIVATE KEY\" PEM block")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: parse key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("walletprovider: key must be P-256")
	}
	return &Provider{Issuer: issuer, Key: key}, nil
}

// PrivateKeyPEM encodes the provider's private key as PEM. Treat the
// result as a secret: anyone holding it can attest wallets this demo
// issuer will accept.
func (p *Provider) PrivateKeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(p.Key)
	if err != nil {
		return nil, fmt.Errorf("walletprovider: marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// PublicJWKS returns the provider's public key as a JWK Set — what the
// issuer registers to verify this provider's attestations.
func (p *Provider) PublicJWKS() ([]byte, error) {
	raw, err := p.Key.PublicKey.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		return nil, fmt.Errorf("walletprovider: encode public key: %w", err)
	}
	size := (len(raw) - 1) / 2
	b64 := base64.RawURLEncoding
	return json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "EC", "crv": "P-256", "kid": KeyID, "alg": "ES256", "use": "sig",
		"x": b64.EncodeToString(raw[1 : 1+size]), "y": b64.EncodeToString(raw[1+size:]),
	}}})
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
