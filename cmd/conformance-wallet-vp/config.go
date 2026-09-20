package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
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
	// conformance/wallet-vp/README.md's own "Open questions". Only
	// used when CredentialFormat is "" or "dc+sd-jwt".
	VCT    string            `json:"vct"`
	Claims map[string]string `json:"claims"`

	// CredentialFormat selects which fixture credential this binary
	// issues and presents: "" (default) or credential/sdjwtvc.CredentialFormat
	// ("dc+sd-jwt") both mean the SD-JWT VC fixture (VCT/Claims below);
	// credential/mdoc.CredentialFormat ("mso_mdoc") means the mdoc
	// fixture (MdocDocType/MdocNamespace/MdocClaims/Mdoc* key material
	// below instead) — see credential.go's own issueFixtureCredential/
	// issueFixtureMdocCredential.
	CredentialFormat string `json:"credential_format,omitempty"`

	// MdocIssuerPrivateKeyPEM/MdocIssuerCertificatePEM are this
	// binary's own mdoc Document Signer identity — the mdoc-format
	// analog of CredentialIssuerPrivateKeyPEM/CredentialIssuerCertificatePEM
	// above, a separate key/cert pair since ISO/IEC 18013-5's own IACA/
	// Document Signer certificate profile (internal/conformancecert.
	// GenerateMdocIACA/GenerateMdocDocumentSigner) differs from the
	// plain leaf-under-CA shape credential_issuer_certificate_pem uses.
	// Only required when CredentialFormat is "mso_mdoc".
	MdocIssuerPrivateKeyPEM  string `json:"mdoc_issuer_private_key_pem,omitempty"`
	MdocIssuerCertificatePEM string `json:"mdoc_issuer_certificate_pem,omitempty"`

	// MdocDocType/MdocNamespace/MdocClaims describe the fixture mdoc
	// this binary presents — the mdoc-format analog of VCT/Claims
	// above. Only required when CredentialFormat is "mso_mdoc".
	MdocDocType   string            `json:"mdoc_doc_type,omitempty"`
	MdocNamespace string            `json:"mdoc_namespace,omitempty"`
	MdocClaims    map[string]string `json:"mdoc_claims,omitempty"`
}

// isMdoc reports whether c is configured for the "mso_mdoc" fixture
// credential rather than the default "dc+sd-jwt" one.
func (c Config) isMdoc() bool {
	return c.CredentialFormat == mdoc.CredentialFormat
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
	if cfg.HolderPrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("config: holder_private_key_pem is required")
	}
	if cfg.isMdoc() {
		if cfg.MdocIssuerPrivateKeyPEM == "" {
			return Config{}, fmt.Errorf("config: mdoc_issuer_private_key_pem is required")
		}
		if err := conformancecert.RequireNonEmpty("mdoc_issuer_certificate_pem", cfg.MdocIssuerCertificatePEM); err != nil {
			return Config{}, err
		}
		if cfg.MdocDocType == "" {
			return Config{}, fmt.Errorf("config: mdoc_doc_type is required")
		}
		if cfg.MdocNamespace == "" {
			return Config{}, fmt.Errorf("config: mdoc_namespace is required")
		}
		if len(cfg.MdocClaims) == 0 {
			return Config{}, fmt.Errorf("config: mdoc_claims must be non-empty")
		}
		return cfg, nil
	}
	if cfg.CredentialIssuerPrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("config: credential_issuer_private_key_pem is required")
	}
	if err := conformancecert.RequireNonEmpty("credential_issuer_certificate_pem", cfg.CredentialIssuerCertificatePEM); err != nil {
		return Config{}, err
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

func (c Config) credentialIssuerKey() (*ecdsa.PrivateKey, error) {
	key, err := conformancecert.ParseECPrivateKeyPEM(c.CredentialIssuerPrivateKeyPEM)
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
	key, err := conformancecert.ParseECPrivateKeyPEM(c.HolderPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("holder_private_key_pem: %w", err)
	}
	return key, nil
}

func (c Config) mdocIssuerKey() (*ecdsa.PrivateKey, error) {
	key, err := conformancecert.ParseECPrivateKeyPEM(c.MdocIssuerPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("mdoc_issuer_private_key_pem: %w", err)
	}
	return key, nil
}

func (c Config) mdocIssuerCertificate() (*x509.Certificate, error) {
	cert, err := conformancecert.ParseCertificatePEM(c.MdocIssuerCertificatePEM)
	if err != nil {
		return nil, fmt.Errorf("mdoc_issuer_certificate_pem: %w", err)
	}
	return cert, nil
}
