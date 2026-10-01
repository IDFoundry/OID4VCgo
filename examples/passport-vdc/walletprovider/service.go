package walletprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
)

// The service's paths, relative to its URL.
const (
	WalletAttestationPath = "/wallet-attestation"
	KeyAttestationPath    = "/key-attestation"
)

const (
	// WalletAttestationLifetime is how long a Wallet Attestation the
	// service issues is valid.
	WalletAttestationLifetime = time.Hour
	// KeyAttestationLifetime is how long a Key Attestation the service
	// issues is valid: it's used once, right away.
	KeyAttestationLifetime = 5 * time.Minute

	maxRequestBytes = 16 * 1024
	maxAttestedKeys = 10
	maxNonceLength  = 256
)

// WalletAttestationRequest asks the service for a Wallet Attestation
// binding InstanceKey, a public JWK, to ClientID.
type WalletAttestationRequest struct {
	ClientID    string          `json:"client_id"`
	InstanceKey json.RawMessage `json:"instance_key"`
}

// KeyAttestationRequest asks the service for a Key Attestation over
// Keys, public JWKs, carrying the Credential Issuer's Nonce.
type KeyAttestationRequest struct {
	Keys  []json.RawMessage `json:"keys"`
	Nonce string            `json:"nonce"`
}

// AttestationResponse is the service's answer to either request.
type AttestationResponse struct {
	Attestation string `json:"attestation"`
}

// KeyAttestation issues a Key Attestation over keys carrying nonce, the
// Credential Issuer's c_nonce (HAIP 1.0 §4.5.1), issued at now and valid
// for lifetime. It asserts no key_storage or user_authentication level:
// the demo's holder keys are ordinary software keys.
func (p *Provider) KeyAttestation(keys []*ecdsa.PublicKey, nonce string, now time.Time, lifetime time.Duration) (string, error) {
	claims, err := p.KeyAttestationClaims(keys, now, lifetime)
	if err != nil {
		return "", err
	}
	claims.IssuedAt, claims.Nonce = now.Unix(), nonce
	jwt, err := attestation.Issue(p.Key, oid4vci.ES256, p.x5cHeader(), claims)
	if err != nil {
		return "", fmt.Errorf("walletprovider: key attestation: %w", err)
	}
	return jwt, nil
}

// Handler serves the provider as a service the demo wallets call, so
// they never hold its key: POST WalletAttestationPath with a
// WalletAttestationRequest, or KeyAttestationPath with a
// KeyAttestationRequest, answered with an AttestationResponse.
//
// It attests only clientID, the demo wallet's registration with the
// issuer. It attests any key it's sent, and doesn't authenticate the
// wallet asking: a real Wallet Provider would first check platform
// evidence that the request comes from a genuine instance of its wallet
// and that the keys are held in secure hardware.
func (p *Provider) Handler(clientID string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+WalletAttestationPath, func(w http.ResponseWriter, r *http.Request) {
		var req WalletAttestationRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		if req.ClientID != clientID {
			writeError(w, http.StatusForbidden, fmt.Sprintf("this Wallet Provider attests only client %q", clientID))
			return
		}
		key, err := parseP256Key(req.InstanceKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "instance_key: "+err.Error())
			return
		}
		jwt, err := p.Attest(clientID, key, time.Now(), WalletAttestationLifetime)
		writeAttestation(w, jwt, err)
	})
	mux.HandleFunc("POST "+KeyAttestationPath, func(w http.ResponseWriter, r *http.Request) {
		var req KeyAttestationRequest
		if !decodeRequest(w, r, &req) {
			return
		}
		if len(req.Keys) == 0 || len(req.Keys) > maxAttestedKeys {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("keys must hold 1 to %d keys", maxAttestedKeys))
			return
		}
		if !validNonce(req.Nonce) {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("nonce must be 1 to %d printable ASCII characters", maxNonceLength))
			return
		}
		keys := make([]*ecdsa.PublicKey, len(req.Keys))
		for i, raw := range req.Keys {
			key, err := parseP256Key(raw)
			if err != nil {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("keys[%d]: %v", i, err))
				return
			}
			keys[i] = key
		}
		jwt, err := p.KeyAttestation(keys, req.Nonce, time.Now(), KeyAttestationLifetime)
		writeAttestation(w, jwt, err)
	})
	return mux
}

// decodeRequest reads a JSON request body of at most maxRequestBytes
// into v, answering 400 and reporting false if it can't.
func decodeRequest(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "malformed request: "+err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "malformed request: data after the JSON object")
		return false
	}
	return true
}

// validNonce reports whether nonce, signed into a Key Attestation, is a
// plausible c_nonce: 1 to maxNonceLength printable ASCII characters.
func validNonce(nonce string) bool {
	if nonce == "" || len(nonce) > maxNonceLength {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		if nonce[i] < 0x21 || nonce[i] > 0x7e {
			return false
		}
	}
	return true
}

// hasPrivateMember reports whether the JSON object raw has a "d" member
// — EC's private key — under any spelling encoding/json would match, and
// however many times it's repeated (decoding keeps only the last).
func hasPrivateMember(raw json.RawMessage) bool {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return false
	}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return false
		}
		if name, ok := key.(string); ok && strings.EqualFold(name, "d") {
			return true
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return false
		}
	}
	return false
}

// parseP256Key parses raw as a public EC P-256 JWK.
func parseP256Key(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var jwk oid4vci.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, errors.New("not a JWK")
	}
	if hasPrivateMember(raw) {
		return nil, errors.New("a private key was sent")
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 key")
	}
	return key, nil
}

func writeAttestation(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue the attestation")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(AttestationResponse{Attestation: jwt})
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
