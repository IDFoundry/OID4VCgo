package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/statuslist"
	"github.com/idfoundry/oid4vcgo/verifier"
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
	// resolution. REQUIRED for "dc+sd-jwt", unless
	// CredentialIssuerTrustAnchorsPEM is set instead.
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

	// MdocTrustAnchorPEM is the mdoc IACA root certificate this binary
	// trusts to verify a presented "mso_mdoc" credential's own
	// IssuerAuth x5chain — the suite's own well-known, fixed
	// "certification.openid.net" test root (confirmed live by decoding
	// a real DeviceResponse's own x5chain; served at the suite's own
	// GET /mdoc-iaca-root.pem, which
	// internal/conformanceverifier.fetchMdocIACARootPEM fetches when
	// generating this config), never a per-run/per-candidate value.
	// REQUIRED when CredentialFormat is "mso_mdoc"; ignored otherwise.
	MdocTrustAnchorPEM string `json:"mdoc_trust_anchor_pem"`

	// The fields below are for interop runs against other wallets
	// (interop/eudi/run-wallet.sh), not the OIDF suite, whose
	// configuration leaves them unset.

	// CredentialIssuerTrustAnchorsPEM, when set, trusts a "dc+sd-jwt"
	// Credential Issuer by its x5c chain to one of these CA
	// certificates (verifier.X5CIssuerKeyResolver) instead of by
	// CredentialIssuerJWK: exactly one of the two is REQUIRED for
	// "dc+sd-jwt".
	CredentialIssuerTrustAnchorsPEM string `json:"credential_issuer_trust_anchors_pem"`

	// StatusListTrustAnchorsPEM, when set, turns on the Token Status
	// List check (verifier.StatusPolicy): every presented credential
	// must carry a status reference, its Status List Token must be
	// signed by the credential's own issuer, chaining to one of these
	// CA certificates, and its status must be valid. Unset, no status
	// is checked: the OIDF suite's per-run issuer publishes no status
	// list.
	StatusListTrustAnchorsPEM string `json:"status_list_trust_anchors_pem"`

	// StatusListTLSTrustAnchorsPEM, if set, are the CA certificates
	// the status list fetch trusts for TLS, in place of the system
	// roots.
	StatusListTLSTrustAnchorsPEM string `json:"status_list_tls_trust_anchors_pem"`

	// StatusListAllowLoopback lets the status list fetch reach a
	// loopback address, as a local run's status lists are served on
	// localhost.
	StatusListAllowLoopback bool `json:"status_list_allow_loopback"`

	// DCAPIOrigins, when set, enables the Digital Credentials API
	// endpoints (POST /dcapi/request, POST /dcapi/response/{id}): each
	// request is for one of these origins, and lists them all as its
	// expected_origins.
	DCAPIOrigins []string `json:"dc_api_origins"`
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
	if err := cfg.checkFormat(); err != nil {
		return Config{}, err
	}
	if cfg.StatusListTrustAnchorsPEM == "" && (cfg.StatusListTLSTrustAnchorsPEM != "" || cfg.StatusListAllowLoopback) {
		return Config{}, fmt.Errorf("config: status_list_tls_trust_anchors_pem and status_list_allow_loopback need status_list_trust_anchors_pem")
	}
	return cfg, nil
}

// checkFormat checks the settings CredentialFormat's credential needs.
func (c Config) checkFormat() error {
	switch c.CredentialFormat {
	case "", "dc+sd-jwt":
		if c.hasCredentialIssuerJWK() == (c.CredentialIssuerTrustAnchorsPEM != "") {
			return fmt.Errorf("config: exactly one of credential_issuer_jwk and credential_issuer_trust_anchors_pem is required")
		}
		if c.VCT == "" {
			return fmt.Errorf("config: vct is required")
		}
		if len(c.Claims) == 0 {
			return fmt.Errorf("config: claims must be non-empty")
		}
	case "mso_mdoc":
		if c.Doctype == "" {
			return fmt.Errorf("config: doctype is required")
		}
		if c.Namespace == "" {
			return fmt.Errorf("config: namespace is required")
		}
		if len(c.MdocClaims) == 0 {
			return fmt.Errorf("config: mdoc_claims must be non-empty")
		}
		return conformancecert.RequireNonEmpty("mdoc_trust_anchor_pem", c.MdocTrustAnchorPEM)
	default:
		return fmt.Errorf("config: unsupported credential_format %q", c.CredentialFormat)
	}
	return nil
}

// hasCredentialIssuerJWK reports whether CredentialIssuerJWK is set.
func (c Config) hasCredentialIssuerJWK() bool {
	return len(c.CredentialIssuerJWK) != 0 && string(c.CredentialIssuerJWK) != "null"
}

// sdJWTVCIssuerKeys is the "dc+sd-jwt" Credential Issuer trust that
// CredentialIssuerTrustAnchorsPEM or CredentialIssuerJWK configures:
// nil when neither is set, as an "mso_mdoc" configuration may leave
// them.
func (c Config) sdJWTVCIssuerKeys() (verifier.SDJWTVCIssuerKeyResolver, error) {
	if c.CredentialIssuerTrustAnchorsPEM != "" {
		roots, err := certPool("credential_issuer_trust_anchors_pem", c.CredentialIssuerTrustAnchorsPEM)
		if err != nil {
			return nil, err
		}
		// No revocation check of the issuer's certificate: an interop
		// run's throwaway CA publishes no CRL. The credential's own
		// revocation is its status list's.
		return verifier.X5CIssuerKeyResolver{Roots: roots, Revocation: certrevocation.NoCheck{}}, nil
	}
	if !c.hasCredentialIssuerJWK() {
		return nil, nil
	}
	return newStaticIssuerKeyResolver(c.CredentialIssuerJWK)
}

// statusListFetchTimeout bounds one status list fetch.
const statusListFetchTimeout = 30 * time.Second

// statusPolicy is the Token Status List check StatusListTrustAnchorsPEM
// turns on: nil when it's unset.
func (c Config) statusPolicy() (*verifier.StatusPolicy, error) {
	if c.StatusListTrustAnchorsPEM == "" {
		return nil, nil
	}
	roots, err := certPool("status_list_trust_anchors_pem", c.StatusListTrustAnchorsPEM)
	if err != nil {
		return nil, err
	}
	fetcher := statuslist.Fetcher{AllowLoopback: c.StatusListAllowLoopback}
	if c.StatusListTLSTrustAnchorsPEM != "" {
		tlsRoots, err := certPool("status_list_tls_trust_anchors_pem", c.StatusListTLSTrustAnchorsPEM)
		if err != nil {
			return nil, err
		}
		fetcher.HTTP = &http.Client{
			Timeout:   statusListFetchTimeout,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: tlsRoots, MinVersion: tls.VersionTLS12}},
		}
	}
	return &verifier.StatusPolicy{
		Checker:          statuslist.Checker{Fetcher: fetcher, Roots: roots},
		RequireReference: true,
	}, nil
}

// certPool parses pemStr, the value of the config field named field,
// into an *x509.CertPool.
func certPool(field, pemStr string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemStr)) {
		return nil, fmt.Errorf("%s: no certificate found", field)
	}
	return pool, nil
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

// mdocTrustAnchorPool parses MdocTrustAnchorPEM into the *x509.CertPool
// verifier.X5ChainIssuerKeyResolver needs as its own Roots.
func (c Config) mdocTrustAnchorPool() (*x509.CertPool, error) {
	return certPool("mdoc_trust_anchor_pem", c.MdocTrustAnchorPEM)
}
