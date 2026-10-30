package walletprovider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/attestation"
	"github.com/idfoundry/oid4vcgo/examples/passport-vdc/internal/androidattest"
)

// The service's paths, relative to its URL.
const (
	WalletAttestationPath = "/wallet-attestation"
	KeyAttestationPath    = "/key-attestation"
	ChallengePath         = "/attestation-challenge"
)

const (
	// WalletAttestationLifetime is how long a Wallet Attestation the
	// service issues is valid.
	WalletAttestationLifetime = time.Hour
	// KeyAttestationLifetime is how long a Key Attestation the service
	// issues is valid. Its c_nonce makes it fresh when it's sent, but
	// its exp is when the keys it attests expire too (OpenID4VCI 1.0
	// Appendix D.1), which the issuer checks again when a review it
	// deferred issuance for is approved: it outlasts that review.
	KeyAttestationLifetime = 2 * time.Hour

	// maxRequestBytes fits maxAttestedKeys keys with their attestation
	// chains.
	maxRequestBytes = 256 * 1024
	maxAttestedKeys = 10
	maxNonceLength  = 256
)

// WalletAttestationRequest asks the service for a Wallet Attestation
// binding InstanceKey, a public JWK, to ClientID. An Android wallet
// sends the key's Android Key Attestation chain, made over a challenge
// from ChallengePath, as InstanceKeyCertificateChain.
type WalletAttestationRequest struct {
	ClientID    string          `json:"client_id"`
	InstanceKey json.RawMessage `json:"instance_key"`
	// InstanceKeyCertificateChain is the key's certificate chain, each
	// certificate base64 (not base64url) DER, the key's own first, as
	// in x5c.
	InstanceKeyCertificateChain []string `json:"instance_key_certificate_chain,omitempty"`
}

// KeyAttestationRequest asks the service for a Key Attestation over
// Keys, public JWKs, carrying the Credential Issuer's Nonce. An Android
// wallet sends each key's Android Key Attestation chain in
// CertificateChains, in the order of Keys (an empty chain for a key it
// has none for).
type KeyAttestationRequest struct {
	Keys              []json.RawMessage `json:"keys"`
	Nonce             string            `json:"nonce"`
	CertificateChains [][]string        `json:"certificate_chains,omitempty"`
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

// ServiceConfig configures the provider's service.
type ServiceConfig struct {
	// ClientID is the demo wallet's registration with the issuer, the
	// only client the service attests.
	ClientID string
	// RequireHardwareKeyAttestation refuses a key whose Android Key
	// Attestation chain is verified but not one Google vouches for: it
	// doesn't end at a Google hardware attestation root, a certificate
	// in it is outside its validity, or it says the key or the
	// attestation is in software (an emulator). Without it they're
	// attested, and logged. A key sent without a chain (from iOS, the
	// CLI or web wallet, or an older app) is attested either way.
	RequireHardwareKeyAttestation bool
	// VerifiedKeysPath is the file that keeps the keys whose chains the
	// service verified, so a key re-attested after a restart is still
	// recognised; empty keeps them in memory only.
	VerifiedKeysPath string
	// AttestationRoots are the roots a hardware chain ends at; nil
	// means Google's hardware attestation roots.
	AttestationRoots []*x509.Certificate
	// Logf logs each attestation and what was made of its evidence; nil
	// means log.Printf.
	Logf func(format string, args ...any)
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Handler serves the provider for clientID with the defaults of
// ServiceConfig: see NewService.
func (p *Provider) Handler(clientID string) http.Handler {
	h, err := p.NewService(ServiceConfig{ClientID: clientID})
	if err != nil { // only reading VerifiedKeysPath fails
		panic(err)
	}
	return h
}

// NewService serves the provider as a service the demo wallets call, so
// they never hold its key: POST WalletAttestationPath with a
// WalletAttestationRequest, or KeyAttestationPath with a
// KeyAttestationRequest, answered with an AttestationResponse; POST
// ChallengePath with a ChallengeRequest for a ChallengeResponse.
//
// It attests only cfg.ClientID. A key sent with an Android Key
// Attestation chain is attested only if the chain's signatures hold,
// it certifies that key, and its challenge is one the service issued
// for the key's purpose, unused and unexpired (or the chain is one the
// service verified for this key before); whether it's also hardware
// Google vouches for is logged, and required with
// cfg.RequireHardwareKeyAttestation. A key sent without a chain is
// attested as before, and logged as such. It doesn't authenticate the
// wallet asking.
func (p *Provider) NewService(cfg ServiceConfig) (http.Handler, error) {
	s, err := p.newService(cfg)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+ChallengePath, s.challenge)
	mux.HandleFunc("POST "+WalletAttestationPath, s.walletAttestation)
	mux.HandleFunc("POST "+KeyAttestationPath, s.keyAttestation)
	return mux, nil
}

func (p *Provider) newService(cfg ServiceConfig) (*service, error) {
	if cfg.AttestationRoots == nil {
		cfg.AttestationRoots = androidattest.GoogleRoots()
	}
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	ev, err := newEvidence(cfg.AttestationRoots, cfg.Now, cfg.VerifiedKeysPath, cfg.Logf)
	if err != nil {
		return nil, err
	}
	return &service{p: p, cfg: cfg, ev: ev}, nil
}

type service struct {
	p   *Provider
	cfg ServiceConfig
	ev  *evidence
}

func (s *service) challenge(w http.ResponseWriter, r *http.Request) {
	var req ChallengeRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.Purpose != PurposeInstance && req.Purpose != PurposeHolder {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("purpose must be %q or %q", PurposeInstance, PurposeHolder))
		return
	}
	c, err := s.ev.challenge(req.Purpose)
	if errors.Is(err, errTooManyChallenges) {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not make a challenge")
		return
	}
	writeJSON(w, ChallengeResponse{Challenge: base64.RawURLEncoding.EncodeToString(c), ExpiresIn: int(ChallengeLifetime / time.Second)})
}

func (s *service) walletAttestation(w http.ResponseWriter, r *http.Request) {
	var req WalletAttestationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if req.ClientID != s.cfg.ClientID {
		writeError(w, http.StatusForbidden, fmt.Sprintf("this Wallet Provider attests only client %q", s.cfg.ClientID))
		return
	}
	key, thumbprint, err := parseP256Key(req.InstanceKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "instance_key: "+err.Error())
		return
	}
	outcome, ok := s.checkEvidence(w, "Wallet Attestation", "instance key", PurposeInstance, key, thumbprint, req.InstanceKeyCertificateChain)
	if !ok {
		return
	}
	jwt, err := s.p.Attest(s.cfg.ClientID, key, s.cfg.Now(), WalletAttestationLifetime)
	if err == nil {
		s.cfg.Logf("wallet provider: Wallet Attestation for instance key %s: %s", thumbprint, outcome)
	}
	writeAttestation(w, jwt, err)
}

func (s *service) keyAttestation(w http.ResponseWriter, r *http.Request) {
	var req KeyAttestationRequest
	if !decodeRequest(w, r, &req) {
		return
	}
	if len(req.Keys) == 0 || len(req.Keys) > maxAttestedKeys {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("keys must hold 1 to %d keys", maxAttestedKeys))
		return
	}
	if req.CertificateChains != nil && len(req.CertificateChains) != len(req.Keys) {
		writeError(w, http.StatusBadRequest, "certificate_chains must have one chain for each key")
		return
	}
	if !validNonce(req.Nonce) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("nonce must be 1 to %d printable ASCII characters", maxNonceLength))
		return
	}
	keys := make([]*ecdsa.PublicKey, len(req.Keys))
	thumbprints := make([]string, len(req.Keys))
	for i, raw := range req.Keys {
		key, thumbprint, err := parseP256Key(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("keys[%d]: %v", i, err))
			return
		}
		keys[i], thumbprints[i] = key, thumbprint
	}
	outcomes := make([]string, len(keys))
	for i, key := range keys {
		var chain []string
		if req.CertificateChains != nil {
			chain = req.CertificateChains[i]
		}
		outcome, ok := s.checkEvidence(w, "Key Attestation", fmt.Sprintf("keys[%d]", i), PurposeHolder, key, thumbprints[i], chain)
		if !ok {
			return
		}
		outcomes[i] = outcome
	}
	jwt, err := s.p.KeyAttestation(keys, req.Nonce, s.cfg.Now(), KeyAttestationLifetime)
	if err == nil {
		for i, outcome := range outcomes {
			s.cfg.Logf("wallet provider: Key Attestation for holder key %s: %s", thumbprints[i], outcome)
		}
	}
	writeAttestation(w, jwt, err)
}

// checkEvidence checks a key's attestation chain, if it was sent one,
// answering 403 and reporting false for one to refuse; it returns what
// it made of it, to log.
func (s *service) checkEvidence(w http.ResponseWriter, what, name, purpose string, key *ecdsa.PublicKey, thumbprint string, chain []string) (string, bool) {
	if len(chain) == 0 {
		return "no key attestation chain (attested as before, unverified)", true
	}
	outcome, err := s.ev.check(purpose, key, thumbprint, chain)
	if err == nil && s.cfg.RequireHardwareKeyAttestation && !outcome.Hardware {
		err = fmt.Errorf("this Wallet Provider requires hardware key attestation: %s", strings.Join(outcome.Issues, "; "))
	}
	if err != nil {
		s.cfg.Logf("wallet provider: refused a %s for %s %s: %v", what, name, thumbprint, err)
		writeError(w, http.StatusForbidden, fmt.Sprintf("%s: key attestation: %v", name, err))
		return "", false
	}
	return outcome.String(), true
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

// parseP256Key parses raw as a public EC P-256 JWK, returning it with
// its JWK thumbprint (RFC 7638).
func parseP256Key(raw json.RawMessage) (*ecdsa.PublicKey, string, error) {
	var jwk oid4vci.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, "", errors.New("not a JWK")
	}
	if hasPrivateMember(raw) {
		return nil, "", errors.New("a private key was sent")
	}
	pub, err := jwk.PublicKey()
	if err != nil {
		return nil, "", err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, "", errors.New("not an EC P-256 key")
	}
	thumbprint, err := jwk.Thumbprint()
	if err != nil {
		return nil, "", err
	}
	return key, thumbprint, nil
}

func writeAttestation(w http.ResponseWriter, jwt string, err error) {
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue the attestation")
		return
	}
	writeJSON(w, AttestationResponse{Attestation: jwt})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
