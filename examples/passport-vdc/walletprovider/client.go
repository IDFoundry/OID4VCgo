package walletprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/idfoundry/oid4vcgo/attestation"
)

// maxResponseBytes bounds the service's answer a Client reads.
const maxResponseBytes = 64 * 1024

// Client asks a Wallet Provider service (Provider.Handler) for
// attestations, so the wallet never holds the provider's key.
type Client struct {
	// URL is the service's base URL, e.g. https://127.0.0.1:6443.
	URL string
	// HTTP makes the requests; nil means a client with a 10 s timeout.
	HTTP *http.Client
}

// WalletAttestation asks for a Wallet Attestation binding instanceKey,
// the wallet instance's Client Attestation PoP key, to clientID.
func (c Client) WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	jwk, err := attestation.AttestedKey(instanceKey)
	if err != nil {
		return "", fmt.Errorf("walletprovider: instance key: %w", err)
	}
	return c.post(ctx, WalletAttestationPath, WalletAttestationRequest{ClientID: clientID, InstanceKey: jwk})
}

// KeyAttestation asks for a Key Attestation over keys carrying nonce,
// the Credential Issuer's c_nonce.
func (c Client) KeyAttestation(ctx context.Context, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	jwks := make([]json.RawMessage, len(keys))
	for i, k := range keys {
		jwk, err := attestation.AttestedKey(k)
		if err != nil {
			return "", fmt.Errorf("walletprovider: key %d: %w", i, err)
		}
		jwks[i] = jwk
	}
	return c.post(ctx, KeyAttestationPath, KeyAttestationRequest{Keys: jwks, Nonce: nonce})
}

func (c Client) post(ctx context.Context, path string, body any) (string, error) {
	payload, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(c.URL, "/")+path, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("walletprovider: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return "", fmt.Errorf("walletprovider: %s: HTTP %d: %s", path, resp.StatusCode, e.Error)
	}
	var out AttestationResponse
	if err := json.Unmarshal(data, &out); err != nil || out.Attestation == "" {
		return "", fmt.Errorf("walletprovider: %s: malformed response", path)
	}
	return out.Attestation, nil
}
