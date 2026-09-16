package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcigo/internal/conformancecert"
)

// Config is this binary's own configuration — one JSON file, inline
// key material, the same shape cmd/conformance-verifier's own Config
// uses.
type Config struct {
	// ListenAddr is the TLS listener's own bind address — this is
	// what the OIDF suite's test configuration registers as
	// "server.authorization_endpoint" (plus this binary's own path,
	// "/authorize").
	ListenAddr string `json:"listen_addr"`

	TLSCertificatePEM string `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM  string `json:"tls_private_key_pem"`

	// CredentialIssuerPrivateKeyPEM signs this binary's own fixture
	// SD-JWT VC (see credential.go).
	CredentialIssuerPrivateKeyPEM string `json:"credential_issuer_private_key_pem"`

	// CredentialIssuerCertificatePEM is a self-signed leaf certificate
	// wrapping CredentialIssuerPrivateKeyPEM's own public key — set as
	// the fixture credential's own "x5c" header (RFC 7515 §4.1.6),
	// confirmed live as what HAIP's own SD-JWT VC trust model requires
	// (the OIDF conformance suite's own "Credential MUST contain an x5c
	// in the header" check) — paste its PEM into the suite's own
	// credential-trust test-configuration field
	// ("credential.trust_anchor_pem").
	CredentialIssuerCertificatePEM string `json:"credential_issuer_certificate_pem"`

	// HolderPrivateKeyPEM is the fixture credential's own Holder
	// Binding key (its "cnf" claim's public half, and what signs the
	// Key Binding JWT on presentation).
	HolderPrivateKeyPEM string `json:"holder_private_key_pem"`

	// VCT/Claims describe the fixture SD-JWT VC this binary presents.
	// Must match whatever DCQL query the suite's own test
	// configuration asks for (either one of its built-in queries, or
	// a "client.dcql" custom query naming the same vct/claims) — see
	// conformance/wallet-vp/README.md's own "Open questions".
	VCT    string            `json:"vct"`
	Claims map[string]string `json:"claims"`
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
	if cfg.CredentialIssuerPrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("config: credential_issuer_private_key_pem is required")
	}
	if err := conformancecert.RequireNonEmpty("credential_issuer_certificate_pem", cfg.CredentialIssuerCertificatePEM); err != nil {
		return Config{}, err
	}
	if cfg.HolderPrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("config: holder_private_key_pem is required")
	}
	if cfg.VCT == "" {
		return Config{}, fmt.Errorf("config: vct is required")
	}
	if len(cfg.Claims) == 0 {
		return Config{}, fmt.Errorf("config: claims must be non-empty")
	}
	return cfg, nil
}

func (c Config) tlsCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(c.TLSCertificatePEM), []byte(c.TLSPrivateKeyPEM))
}

func parseECPrivateKeyPEM(raw string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func (c Config) credentialIssuerKey() (*ecdsa.PrivateKey, error) {
	key, err := parseECPrivateKeyPEM(c.CredentialIssuerPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("credential_issuer_private_key_pem: %w", err)
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

func (c Config) holderPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := parseECPrivateKeyPEM(c.HolderPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("holder_private_key_pem: %w", err)
	}
	return key, nil
}
