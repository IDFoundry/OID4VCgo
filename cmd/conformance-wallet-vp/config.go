package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/wallet"
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

	// VerifierTrustAnchorsPEM, if set, are the trust anchors a
	// Verifier's Request Object certificate chain must verify against
	// (OID4VP §5.9.3, HAIP 1.0 §5): its x5c leaf must be issued, not
	// self-signed, by one of them. Unset, the chain isn't checked —
	// only the Request Object's signature and its x509_hash client_id.
	// conformance/wallet-vp/scripts/run-modules sets it to the CA it
	// issues the suite's Request Object signing certificate from.
	VerifierTrustAnchorsPEM string `json:"verifier_trust_anchors_pem,omitempty"`

	// AcceptX509SANDNS also accepts a Request Object whose client_id has
	// the x509_san_dns Client Identifier Prefix (OpenID4VP 1.0 §5.9.3,
	// wallet.ParseAuthorizationRequestParams.AcceptX509SANDNS), and lists
	// it in the wallet_metadata a POST fetch sends. It needs
	// VerifierTrustAnchorsPEM: the name binds the request to nothing
	// without a verified chain.
	AcceptX509SANDNS bool `json:"accept_x509_san_dns,omitempty"`

	// VerifierTLSTrustAnchorsPEM, if set, are the certificates the
	// Verifier's TLS server certificate is verified against on every
	// call this binary makes to it: fetching request_uri, posting the
	// response, following redirect_uri. A server presenting one of
	// these certificates itself is trusted for any host name (pinned):
	// the OIDF suite's nginx certificate is self-signed for the Common
	// Name localhost, without the subjectAltName Go checks a host name
	// against, and the suite is reached as localhost.emobix.co.uk.
	// Otherwise the server's chain must reach one of them, for the
	// URL's host name. Unset, TLS isn't verified, and the binary says
	// so at startup: a config written before this field existed (the
	// polaris-id interop script's) still runs.
	VerifierTLSTrustAnchorsPEM string `json:"verifier_tls_trust_anchors_pem,omitempty"`

	// Engine is what answers GET /authorize: "" or "wallet" (the
	// default) drives the wallet package directly, step by step;
	// "walletflow" holds the fixture credential in a walletflow.Wallet
	// and answers through walletflow.Wallet.StartPresentation and
	// Presentation.Respond, as a wallet app does, with walletflow's own
	// request_uri fetch and wallet_metadata (see walletflow.go). The
	// conformance plans run the default; the EUDI interop run both.
	Engine string `json:"engine,omitempty"`

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
	// used when CredentialFormat is "" or "dc+sd-jwt". JSON-typed
	// (any), not a plain string, since a spec-complete EUDI PID
	// fixture needs more than plain strings — see MdocClaims's own
	// doc comment for the identical reasoning: "nationalities" is an
	// array, "picture" is a base64-encoded image.
	VCT    string         `json:"vct"`
	Claims map[string]any `json:"claims"`

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

	// MdocCRLPEM/MdocCRLListenAddr, when both set, serve the IACA's
	// CRL (internal/conformancecert.MdocCRLPEM) over plain HTTP on
	// MdocCRLListenAddr at conformancecert.MdocCRLPath — the CRL
	// distribution point MdocIssuerCertificatePEM names (ISO/IEC
	// 18013-5 Table B.3 makes it mandatory), which the OIDF suite
	// fetches and checks for every mdoc it's presented. Only used when
	// CredentialFormat is "mso_mdoc".
	MdocCRLPEM        string `json:"mdoc_crl_pem,omitempty"`
	MdocCRLListenAddr string `json:"mdoc_crl_listen_addr,omitempty"`

	// MdocDocType/MdocNamespace/MdocClaims describe the fixture mdoc
	// this binary presents — the mdoc-format analog of VCT/Claims
	// above. Only required when CredentialFormat is "mso_mdoc".
	// MdocClaims is JSON-typed (any), not a plain string, since a
	// spec-complete org.iso.18013.5.1.mDL fixture needs more than tstr
	// values — see conformanceconfig.MdocConfig.Claims's own doc
	// comment (birth_date/issue_date/expiry_date as full-date-tagged
	// strings, portrait as a base64 string, driving_privileges as a
	// nested array/object) — cmd/conformance-wallet-vp/credential.go's
	// own issueFixtureMdocCredential hands this straight to
	// conformanceconfig.BuildMdocNameSpaceElements, the same transform
	// cmd/conformance-issuer uses.
	MdocDocType   string         `json:"mdoc_doc_type,omitempty"`
	MdocNamespace string         `json:"mdoc_namespace,omitempty"`
	MdocClaims    map[string]any `json:"mdoc_claims,omitempty"`

	// StatusListURI/StatusListIdx, when both set, give the fixture
	// credential, in either format, a Token Status List reference:
	// the SD-JWT VC's "status" claim, or the mdoc MSO's
	// status.status_list. Whoever runs this binary serves the list.
	StatusListURI string  `json:"status_list_uri,omitempty"`
	StatusListIdx *uint64 `json:"status_list_idx,omitempty"`

	// VCTIntegrity, when set, is the fixture SD-JWT VC's
	// "vct#integrity" claim: the integrity of the Type Metadata its
	// vct resolves to. Only used for the SD-JWT VC fixture.
	VCTIntegrity string `json:"vct_integrity,omitempty"`
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
	if cfg.Engine != "" && cfg.Engine != engineWallet && cfg.Engine != engineWalletflow {
		return Config{}, fmt.Errorf("config: engine %q is neither %q nor %q", cfg.Engine, engineWallet, engineWalletflow)
	}
	if (cfg.StatusListURI == "") != (cfg.StatusListIdx == nil) {
		return Config{}, fmt.Errorf("config: status_list_uri and status_list_idx must be set together")
	}
	if cfg.isMdoc() {
		if err := cfg.checkMdoc(); err != nil {
			return Config{}, err
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

// mdocCRL is MdocCRLPEM's DER encoding, or nil when no CRL is
// configured.
func (c Config) mdocCRL() ([]byte, error) {
	if c.MdocCRLPEM == "" {
		return nil, nil
	}
	der, err := conformancecert.ParseCRLPEM(c.MdocCRLPEM)
	if err != nil {
		return nil, fmt.Errorf("mdoc_crl_pem: %w", err)
	}
	return der, nil
}

// verifierTrust is how Request Object certificate chains are trusted:
// against VerifierTrustAnchorsPEM, or not at all when it's unset, which
// AcceptX509SANDNS refuses.
func (c Config) verifierTrust() (wallet.VerifierTrust, error) {
	if c.AcceptX509SANDNS && c.VerifierTrustAnchorsPEM == "" {
		return nil, fmt.Errorf("accept_x509_san_dns needs verifier_trust_anchors_pem")
	}
	if c.VerifierTrustAnchorsPEM == "" {
		return wallet.NoVerifierTrust{}, nil
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(c.VerifierTrustAnchorsPEM)) {
		return nil, fmt.Errorf("verifier_trust_anchors_pem holds no certificate")
	}
	return wallet.X5CVerifierRoots{Roots: roots}, nil
}

// verifierHTTPClient is the client every call to the Verifier goes
// through, verifying its TLS certificate against
// VerifierTLSTrustAnchorsPEM, or, with none, not at all; verified
// reports which.
func (c Config) verifierHTTPClient() (client *http.Client, verified bool, err error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.VerifierTLSTrustAnchorsPEM == "" {
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // no anchors configured: see VerifierTLSTrustAnchorsPEM, and the warning main logs
	} else {
		anchors, err := parseCertificatesPEM(c.VerifierTLSTrustAnchorsPEM)
		if err != nil {
			return nil, false, fmt.Errorf("verifier_tls_trust_anchors_pem: %w", err)
		}
		// Go verifies a chain only for a host name, which a pinned
		// certificate needn't name, so verifyVerifierTLS does it all.
		tlsConfig.InsecureSkipVerify = true //nolint:gosec // verifyVerifierTLS verifies every handshake instead
		tlsConfig.VerifyConnection = func(cs tls.ConnectionState) error { return verifyVerifierTLS(anchors, cs) }
	}
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}, c.VerifierTLSTrustAnchorsPEM != "", nil
}

// parseCertificatesPEM is every CERTIFICATE block in s, of which there
// must be at least one.
func parseCertificatesPEM(s string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(s)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errors.New("holds no certificate")
	}
	return certs, nil
}

// verifyVerifierTLS accepts cs when its server presented one of anchors
// itself, or a chain to one of them that verifies for the host name it
// was dialed as.
func verifyVerifierTLS(anchors []*x509.Certificate, cs tls.ConnectionState) error {
	if len(cs.PeerCertificates) == 0 {
		return errors.New("verifier tls certificate: the server presented none")
	}
	leaf := cs.PeerCertificates[0]
	roots := x509.NewCertPool()
	for _, a := range anchors {
		if bytes.Equal(a.Raw, leaf.Raw) {
			return nil
		}
		roots.AddCert(a)
	}
	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, DNSName: cs.ServerName}); err != nil {
		return fmt.Errorf("verifier tls certificate: %w", err)
	}
	return nil
}

// checkMdoc checks the settings the "mso_mdoc" fixture credential
// needs.
func (c Config) checkMdoc() error {
	if c.MdocIssuerPrivateKeyPEM == "" {
		return fmt.Errorf("config: mdoc_issuer_private_key_pem is required")
	}
	if err := conformancecert.RequireNonEmpty("mdoc_issuer_certificate_pem", c.MdocIssuerCertificatePEM); err != nil {
		return err
	}
	if c.MdocDocType == "" {
		return fmt.Errorf("config: mdoc_doc_type is required")
	}
	if c.MdocNamespace == "" {
		return fmt.Errorf("config: mdoc_namespace is required")
	}
	if len(c.MdocClaims) == 0 {
		return fmt.Errorf("config: mdoc_claims must be non-empty")
	}
	if (c.MdocCRLPEM == "") != (c.MdocCRLListenAddr == "") {
		return fmt.Errorf("config: mdoc_crl_pem and mdoc_crl_listen_addr must be set together")
	}
	return nil
}
