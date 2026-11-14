package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// providerConfig is interop/eudi/scripts/setup-issuer's driver.json, as
// far as the wallet's Wallet Provider uses it: OID4VCgo's issuer
// trusts its attester key and x5c for Wallet Attestations, and its key
// attestation key for Key Attestations.
type providerConfig struct {
	ClientID          string            `json:"client_id"`
	AttesterIssuer    string            `json:"attester_issuer"`
	AttesterKey       map[string]string `json:"attester_key"`
	AttesterX5C       []string          `json:"attester_x5c"`
	KeyAttestationKey map[string]string `json:"key_attestation_key"`
}

// provider is the wallet's Wallet Provider for OID4VCgo's issuer, a
// stand-in signing with setup-issuer's keys, as scripts/serve's
// attester does for Wallet2.
type provider struct {
	cfg              providerConfig
	attester, keyAtt *ecdsa.PrivateKey
}

// loadProvider reads setup-issuer's driver.json at path.
func loadProvider(path string) (*provider, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- the operator's own file
	if err != nil {
		return nil, err
	}
	var cfg providerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	attester, err := ecPrivateKey(cfg.AttesterKey)
	if err != nil {
		return nil, fmt.Errorf("attester_key: %w", err)
	}
	keyAtt, err := ecPrivateKey(cfg.KeyAttestationKey)
	if err != nil {
		return nil, fmt.Errorf("key_attestation_key: %w", err)
	}
	return &provider{cfg: cfg, attester: attester, keyAtt: keyAtt}, nil
}

// WalletAttestation implements walletflow.WalletProvider.
func (p *provider) WalletAttestation(_ context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	now := time.Now()
	return attestation.IssueWalletAttestation(p.attester, oid4vci.ES256, attestation.Header{X5C: p.cfg.AttesterX5C}, attestation.WalletAttestationClaims{
		Issuer: p.cfg.AttesterIssuer, Subject: clientID, InstanceKey: instanceKey,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
	})
}

// KeyAttestation implements walletflow.WalletProvider.
func (p *provider) KeyAttestation(_ context.Context, _ crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	attested := make([]json.RawMessage, 0, len(keys))
	for _, k := range keys {
		raw, err := attestation.AttestedKey(k)
		if err != nil {
			return "", err
		}
		attested = append(attested, raw)
	}
	now := time.Now()
	exp := now.Add(5 * time.Minute).Unix()
	return attestation.Issue(p.keyAtt, oid4vci.ES256, attestation.Header{}, attestation.Claims{
		IssuedAt: now.Unix(), ExpiresAt: &exp, Nonce: nonce, AttestedKeys: attested,
	})
}

var _ walletflow.WalletProvider = (*provider)(nil)

// ecPrivateKey is a P-256 private JWK's key.
func ecPrivateKey(jwk map[string]string) (*ecdsa.PrivateKey, error) {
	d, err := base64.RawURLEncoding.DecodeString(jwk["d"])
	if err != nil {
		return nil, err
	}
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
}

// revoke has the issuer revoke every copy of each credential received,
// as an issuer revokes a credential after issuing it: it POSTs each
// copy's status list entry to url, OID4VCgo's issuer's POST /status
// (cmd/conformance-issuer's statusHandler), and records it in res.
func revoke(ctx context.Context, url string, got []walletflow.StoredCredential, res *result) error {
	for _, c := range got {
		for _, cp := range c.AllCopies() {
			ref := cp.StatusList
			if ref == nil {
				ref = c.StatusList
			}
			if ref == nil {
				return fmt.Errorf("credential %s carries no status list entry to revoke", c.ConfigurationID)
			}
			body, err := json.Marshal(map[string]any{"uri": ref.URI, "idx": ref.Idx, "status": "INVALID"})
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req) // #nosec G107 -- the operator's own loopback URL
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("revoke %s index %d: %s", ref.URI, ref.Idx, resp.Status)
			}
			res.Revoked = append(res.Revoked, fmt.Sprintf("%s#%d", ref.URI, ref.Idx))
		}
	}
	return nil
}
