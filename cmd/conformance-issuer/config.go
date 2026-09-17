package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	fapi "github.com/idfoundry/fapigo"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

// Config is this binary's own configuration — one JSON file, inline
// key material, the same shape cmd/conformance-verifier/-wallet-vp's
// own Config uses.
type Config struct {
	ListenAddr string `json:"listen_addr"`

	// Issuer is this binary's own externally-reachable HTTPS base URL
	// — both the FAPI 2.0 Authorization Server's own "issuer" identity
	// and the OID4VCI Credential Issuer's own identity: one origin
	// plays both roles, matching HAIP's typical combined deployment
	// (issuer/authorization_server.go's own recipe pairs one *Issuer
	// with one *server.Server this same way).
	Issuer string `json:"issuer"`

	TLSCertificatePEM string `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM  string `json:"tls_private_key_pem"`

	// Client is the OIDF suite's own client1 for this test plan.
	Client ConfigClient `json:"client"`

	// Client2 is the OIDF suite's own client2, if this test plan needs
	// a second registered client at all (confirmed live: even this
	// plan's own happy-flow module lists client2.client_id/
	// client2.scope/client2.jwks in its configurationFields, not just
	// negative/multi-client variants — see README's own "Status").
	// Optional: nil registers only Client, matching every scenario that
	// doesn't need a second client at all.
	Client2 *ConfigClient `json:"client2,omitempty"`

	// CredentialIssuerSigningKeyPEM signs every issued "dc+sd-jwt"
	// credential.
	CredentialIssuerSigningKeyPEM string `json:"credential_issuer_signing_key_pem"`

	// CredentialIssuerCertificatePEM is a CA-signed leaf certificate
	// wrapping CredentialIssuerSigningKeyPEM's own public key — set as
	// every issued credential's own "x5c" header (RFC 7515 §4.1.6),
	// confirmed live as what HAIP's own SD-JWT VC trust model requires
	// (the OIDF conformance suite's own "Credential MUST contain an x5c
	// in the header" check, and its "Leaf certificate in x5c chain must
	// not be self-signed" follow-up — see
	// conformance/wallet-vp/README.md for where this was first found).
	// Paste its issuing CA's own PEM into the suite's own
	// "credential.trust_anchor_pem" test-configuration field.
	CredentialIssuerCertificatePEM string `json:"credential_issuer_certificate_pem"`

	// CredentialRequestDecryptionKeyPEM is this issuer's own §10
	// Credential Request decryption key — its public half is published
	// as Metadata's own "credential_request_encryption.jwks" entry
	// (under credentialRequestDecryptionKeyID's own kid, see
	// wiring.go), and issuer.Issuer.DecryptRequestBody uses the private
	// half to decrypt an incoming JWE-encrypted Credential Request.
	// Also used, mirror-image, to satisfy §10's own "if a Wallet's
	// Credential Request asks for an encrypted Response, the request
	// itself must already be encrypted" rule — this binary has no
	// separate response-encryption key of its own, since it always
	// encrypts a Response to whichever public key the Wallet's own
	// "credential_response_encryption.jwk" supplies.
	CredentialRequestDecryptionKeyPEM string `json:"credential_request_decryption_key_pem"`

	// VCT/Claims/Scope/CredentialConfigurationID describe the one
	// CredentialConfiguration this issuer advertises and issues. Claims
	// is this binary's own fixed, canned claim content — issuer.Issuer
	// has no user database of its own (issuer.CredentialRequest.SDJWTClaims'
	// own doc comment), so a caller must always supply real values;
	// this binary's caller-supplied values are just static test data.
	VCT                       string            `json:"vct"`
	Claims                    map[string]string `json:"claims"`
	Scope                     string            `json:"scope"`
	CredentialConfigurationID string            `json:"credential_configuration_id"`

	// DefaultSubject pre-fills the consent page's own subject field —
	// this binary has no real end-user login of its own, matching
	// cmd/conformance-as's identical stance.
	DefaultSubject string `json:"default_subject"`
}

// ConfigClient is Config.Client's own shape: everything needed to
// register one storage.ClientAuthMethodAttestation-authenticated
// client (HAIP §4.4.1's own Wallet Attestation requirement).
// ExpectedAttesterIssuer names who signs a valid Client Attestation
// JWT's own "iss" claim; AttesterJWKS is that same attester's own
// public key(s) — fapigo/server resolves an attestation's verification
// key via Dependencies.ClientKeys keyed by this client's own ID (not
// by ExpectedAttesterIssuer directly, confirmed against
// server/client_auth_attestation.go), so both are required.
type ConfigClient struct {
	ID                     string          `json:"id"`
	RedirectURIs           []string        `json:"redirect_uris"`
	ExpectedAttesterIssuer string          `json:"expected_attester_issuer"`
	AttesterJWKS           json.RawMessage `json:"attester_jwks"`
}

func loadConfig(path string) (Config, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- path is the operator's own -config flag value, not untrusted input
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if cfg.ListenAddr == "" {
		return Config{}, fmt.Errorf("config: listen_addr is required")
	}
	if cfg.Issuer == "" {
		return Config{}, fmt.Errorf("config: issuer is required")
	}
	if err := validateConfigClient("client", cfg.Client); err != nil {
		return Config{}, err
	}
	if cfg.Client2 != nil {
		if err := validateConfigClient("client2", *cfg.Client2); err != nil {
			return Config{}, err
		}
	}
	if cfg.CredentialIssuerSigningKeyPEM == "" {
		return Config{}, fmt.Errorf("config: credential_issuer_signing_key_pem is required")
	}
	if err := conformancecert.RequireNonEmpty("credential_issuer_certificate_pem", cfg.CredentialIssuerCertificatePEM); err != nil {
		return Config{}, err
	}
	if err := conformancecert.RequireNonEmpty("credential_request_decryption_key_pem", cfg.CredentialRequestDecryptionKeyPEM); err != nil {
		return Config{}, err
	}
	if cfg.VCT == "" || len(cfg.Claims) == 0 || cfg.Scope == "" || cfg.CredentialConfigurationID == "" {
		return Config{}, fmt.Errorf("config: vct, claims, scope and credential_configuration_id are all required")
	}
	if cfg.DefaultSubject == "" {
		cfg.DefaultSubject = "conformance-test-subject"
	}
	return cfg, nil
}

// validateConfigClient checks one ConfigClient's own required fields,
// used for both Config.Client (always required) and Config.Client2
// (required to be complete only when present at all).
func validateConfigClient(field string, c ConfigClient) error {
	attesterJWKSEmpty := len(c.AttesterJWKS) == 0 || string(c.AttesterJWKS) == "null"
	if c.ID == "" || len(c.RedirectURIs) == 0 || c.ExpectedAttesterIssuer == "" || attesterJWKSEmpty {
		return fmt.Errorf("config: %s.id, %s.redirect_uris, %s.expected_attester_issuer and %s.attester_jwks are all required", field, field, field, field)
	}
	return nil
}

func (c Config) tlsCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(c.TLSCertificatePEM), []byte(c.TLSPrivateKeyPEM))
}

func (c Config) credentialIssuerSigningKey() (*ecdsa.PrivateKey, error) {
	key, err := conformancecert.ParseECPrivateKeyPEM(c.CredentialIssuerSigningKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("credential_issuer_signing_key_pem: %w", err)
	}
	return key, nil
}

func (c Config) credentialIssuerCertificate() (*x509.Certificate, error) {
	cert, err := conformancecert.ParseCertificatePEM(c.CredentialIssuerCertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("credential_issuer_certificate_pem: %w", err)
	}
	return cert, nil
}

func (c Config) credentialRequestDecryptionKey() (*ecdsa.PrivateKey, error) {
	key, err := conformancecert.ParseECPrivateKeyPEM(c.CredentialRequestDecryptionKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("credential_request_decryption_key_pem: %w", err)
	}
	return key, nil
}

func (c Config) issuerURL() (fapi.URL, error) {
	return fapi.ParseIssuerURL(c.Issuer)
}
