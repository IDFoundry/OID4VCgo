package walletprovider

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"encoding/base64"
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
// attestations, so the wallet never holds the provider's key. It
// doesn't follow redirects, and checks each attestation it gets back is
// over the keys it asked about (and the nonce, client_id) before
// returning it; the issuer verifies its signature and x5c chain.
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
	jwt, err := c.post(ctx, WalletAttestationPath, WalletAttestationRequest{ClientID: clientID, InstanceKey: jwk})
	if err != nil {
		return "", err
	}
	var claims struct {
		Subject string `json:"sub"`
		Cnf     struct {
			JWK json.RawMessage `json:"jwk"`
		} `json:"cnf"`
	}
	if err := decodePayload(jwt, &claims); err != nil || claims.Subject != clientID || !sameKey(claims.Cnf.JWK, jwk) {
		return "", fmt.Errorf("walletprovider: the Wallet Attestation isn't for client %q and the instance key sent", clientID)
	}
	return jwt, nil
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
	jwt, err := c.post(ctx, KeyAttestationPath, KeyAttestationRequest{Keys: jwks, Nonce: nonce})
	if err != nil {
		return "", err
	}
	var claims struct {
		Nonce        string            `json:"nonce"`
		AttestedKeys []json.RawMessage `json:"attested_keys"`
	}
	if err := decodePayload(jwt, &claims); err != nil || claims.Nonce != nonce || len(claims.AttestedKeys) != len(jwks) {
		return "", fmt.Errorf("walletprovider: the Key Attestation isn't over the keys and nonce sent")
	}
	for i := range jwks {
		if !sameKey(claims.AttestedKeys[i], jwks[i]) {
			return "", fmt.Errorf("walletprovider: the Key Attestation isn't over the keys and nonce sent")
		}
	}
	return jwt, nil
}

// decodePayload decodes a compact JWT's payload into v, without
// verifying its signature.
func decodePayload(jwt string, v any) error {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return fmt.Errorf("not a compact JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

// sameKey reports whether two public EC JWKs have the same curve and
// point.
func sameKey(a, b json.RawMessage) bool {
	var ka, kb struct{ Kty, Crv, X, Y string }
	if json.Unmarshal(a, &ka) != nil || json.Unmarshal(b, &kb) != nil {
		return false
	}
	return ka.X != "" && ka == kb
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
	hc := &http.Client{Timeout: 10 * time.Second}
	if c.HTTP != nil {
		copied := *c.HTTP
		hc = &copied
	}
	// A redirect would re-send the request somewhere the wallet wasn't
	// configured to trust as its Wallet Provider.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
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
