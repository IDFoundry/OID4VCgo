package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
)

// Config is this binary's own configuration — loaded from a single
// JSON file (the -config flag), the same "one JSON file, inline key
// material" shape FAPIgo's own conformance/server/oidf-config/*.json
// uses, not a directory of separate PEM/JWK files.
type Config struct {
	// ListenAddr is the TLS listener's own bind address (e.g.
	// ":8443") — the OIDF suite always reaches an implementation
	// under test over HTTPS.
	ListenAddr string `json:"listen_addr"`

	// BaseURL is this binary's own externally-reachable HTTPS base
	// URL (what the suite's own config points at) — used to build
	// every request_uri/response_uri/result URL this binary hands
	// out. No trailing slash.
	BaseURL string `json:"base_url"`

	// TLSCertificatePEM/TLSPrivateKeyPEM are the TLS listener's own
	// server certificate — independent of ClientCertificatePEM
	// below, which is this Verifier's OID4VP Client Identifier, not
	// its transport certificate.
	TLSCertificatePEM string `json:"tls_certificate_pem"`
	TLSPrivateKeyPEM  string `json:"tls_private_key_pem"`

	// ClientCertificatePEM/ClientPrivateKeyPEM are
	// verifier.Config.ClientCertificate/Dependencies.Signer's own
	// source: an EC P-256 leaf certificate (its SHA-256 hash becomes
	// this Verifier's "x509_hash:..." Client Identifier, and its DER
	// encoding the Request Object JWS's own "x5c" header entry) and
	// the matching private key.
	ClientCertificatePEM string `json:"client_certificate_pem"`
	ClientPrivateKeyPEM  string `json:"client_private_key_pem"`

	// CredentialIssuerJWK is the trusted "dc+sd-jwt" Credential
	// Issuer's own signing JWK — statically configured, matching the
	// OIDF suite's own "Credential Issuer" > "Signing JWK" test
	// configuration field (see
	// AbstractCreateSdJwtCredential.createSdJwt in the suite's own
	// source): this binary trusts exactly this key to verify a
	// presented credential's Issuer signature, no dynamic trust
	// resolution. REQUIRED.
	CredentialIssuerJWK json.RawMessage `json:"credential_issuer_jwk"`

	// CredentialFormat selects which DCQL Credential Format buildQuery
	// asks for — "dc+sd-jwt" (the default, when empty) or "mso_mdoc".
	// Only one query is ever built; this binary's job is exercising
	// VerifyResponse's own core verification path for each format, not
	// every DCQL selection permutation in one run.
	CredentialFormat string `json:"credential_format"`

	// VCT/Claims describe the "dc+sd-jwt" DCQL query this binary asks
	// for: the suite's own emulated Credential Issuer defaults to
	// "urn:eudi:pid:1" with claims including given_name/family_name/
	// birthdate/... (see AbstractCreateSdJwtCredential's own source)
	// — Claims should name a subset of those. REQUIRED when
	// CredentialFormat is "dc+sd-jwt" (or empty); ignored otherwise.
	VCT    string   `json:"vct"`
	Claims []string `json:"claims"`

	// Doctype/Namespace/MdocClaims describe the "mso_mdoc" DCQL query
	// this binary asks for instead, when CredentialFormat is
	// "mso_mdoc" — the suite's own emulated mDL Credential Issuer for
	// this test plan defaults to the standard ISO/IEC 18013-5 mDL
	// doctype/namespace ("org.iso.18013.5.1.mDL"/"org.iso.18013.5.1"),
	// with data elements including given_name/family_name/... .
	// REQUIRED when CredentialFormat is "mso_mdoc"; ignored otherwise.
	Doctype    string   `json:"doctype"`
	Namespace  string   `json:"namespace"`
	MdocClaims []string `json:"mdoc_claims"`
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
	if cfg.BaseURL == "" {
		return Config{}, fmt.Errorf("config: base_url is required")
	}
	if len(cfg.CredentialIssuerJWK) == 0 || string(cfg.CredentialIssuerJWK) == "null" {
		return Config{}, fmt.Errorf("config: credential_issuer_jwk is required")
	}
	switch cfg.CredentialFormat {
	case "", "dc+sd-jwt":
		if cfg.VCT == "" {
			return Config{}, fmt.Errorf("config: vct is required")
		}
		if len(cfg.Claims) == 0 {
			return Config{}, fmt.Errorf("config: claims must be non-empty")
		}
	case "mso_mdoc":
		if cfg.Doctype == "" {
			return Config{}, fmt.Errorf("config: doctype is required")
		}
		if cfg.Namespace == "" {
			return Config{}, fmt.Errorf("config: namespace is required")
		}
		if len(cfg.MdocClaims) == 0 {
			return Config{}, fmt.Errorf("config: mdoc_claims must be non-empty")
		}
	default:
		return Config{}, fmt.Errorf("config: unsupported credential_format %q", cfg.CredentialFormat)
	}
	return cfg, nil
}

// tlsCertificate parses Config.TLSCertificatePEM/TLSPrivateKeyPEM into
// a tls.Certificate for the listener.
func (c Config) tlsCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(c.TLSCertificatePEM), []byte(c.TLSPrivateKeyPEM))
}

// clientCertificateAndKey parses ClientCertificatePEM/
// ClientPrivateKeyPEM into the *x509.Certificate/*ecdsa.PrivateKey
// pair verifier.Config/Dependencies need.
func (c Config) clientCertificateAndKey() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	cert, err := conformancecert.ParseCertificatePEM(c.ClientCertificatePEM)
	if err != nil {
		return nil, nil, fmt.Errorf("client_certificate_pem: %w", err)
	}
	key, err := conformancecert.ParseECPrivateKeyPEM(c.ClientPrivateKeyPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("client_private_key_pem: %w", err)
	}
	return cert, key, nil
}
