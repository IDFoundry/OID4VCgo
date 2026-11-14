package main

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"os"

	fapi "github.com/idfoundry/fapigo"
	"github.com/idfoundry/fapigo/storage"

	"github.com/idfoundry/oid4vcgo/internal/conformancecert"
	"github.com/idfoundry/oid4vcgo/internal/conformanceconfig"
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

	// Deferred defers every Credential Request (OID4VCI §9): the
	// Credential Endpoint answers 202 with a transaction_id, and the
	// Deferred Credential Endpoint issues on the Wallet's first poll —
	// what the OIDF suite, which polls once, needs to see the credential.
	Deferred bool `json:"deferred,omitempty"`

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

	// Mdoc, when non-nil, adds a second CredentialConfiguration for
	// credential/mdoc.CredentialFormat ("mso_mdoc") alongside the
	// "dc+sd-jwt" one VCT/Claims/Scope/CredentialConfigurationID above
	// already describes — issued from the same
	// CredentialIssuerSigningKeyPEM/CredentialIssuerCertificatePEM this
	// binary already holds (one issuer identity, two formats) rather
	// than a second throwaway key, matching HAIP's own §6 stance that a
	// Credential Issuer publishing multiple formats does so under one
	// identity. Optional: nil advertises only "dc+sd-jwt", the original
	// single-format behavior. internal/conformanceconfig.MdocConfig,
	// not a locally declared type, so run-fapi2sp-battery's own
	// generator (a separate package main, unable to import this one)
	// shares this exact JSON shape rather than hand-mirroring it.
	Mdoc *conformanceconfig.MdocConfig `json:"mdoc,omitempty"`

	// KeyAttestation, when non-nil, additionally advertises the
	// "attestation" proof type on the "dc+sd-jwt" CredentialConfiguration
	// above — see conformanceconfig.KeyAttestationConfig's own doc
	// comment. Optional: nil leaves today's "jwt"-only behavior
	// unchanged.
	KeyAttestation *conformanceconfig.KeyAttestationConfig `json:"key_attestation,omitempty"`

	// Offers, when set, adds the Pre-Authorized Code Flow (OID4VCI 1.0
	// §3.5) and Credential Offers (§4.1), for a harness driving a Wallet
	// (interop/eudi/run-issuer.sh): the Token Endpoint redeems
	// pre-authorized codes, authenticating the Wallet by its Wallet
	// Attestation as for the authorization code (HAIP 1.0 §4.4.1), the
	// Credential Offer Endpoint serves offers by reference, and a
	// separate plain-HTTP listener on loopback mints offers on request
	// (see offersHandler). The OIDF suite's HAIP issuer plan needs none
	// of this: it tests only the authorization code flow. Optional: nil
	// leaves all of it off.
	Offers *OffersConfig `json:"offers,omitempty"`

	// DPoPNonces has the Authorization Server (PAR and Token Endpoints)
	// and the Credential Issuer's protected endpoints each require a
	// DPoP nonce of their own issuing (RFC 9449 §8, §9), challenging a
	// proof without a valid one with use_dpop_nonce. Off, neither uses
	// nonces.
	DPoPNonces bool `json:"dpop_nonces,omitempty"`

	// AuthorizationDetails has PAR accept openid_credential
	// authorization_details (OpenID4VCI 1.0 §5.1.1, RFC 9396) as well as
	// scopes, and the consent grant each with a credential_identifier it
	// mints (§6.2). Off, the authorization code flow is scope-based.
	AuthorizationDetails bool `json:"authorization_details,omitempty"`

	// StatusLists, when set, gives every Credential issued a Token
	// Status List reference and serves the list (see
	// StatusListsConfig). Off, credentials carry no status.
	StatusLists *StatusListsConfig `json:"status_lists,omitempty"`

	// lists is StatusLists' list, which newServers builds: what the
	// Credential and Deferred Credential Endpoints allocate from, and
	// the offers listener's statusHandler changes.
	lists *statusLists

	// Production, when set, runs the Authorization Server and the
	// Credential Issuer under production assurance (see
	// ProductionConfig). Only a binary built with the
	// conformance_production build tag can: see production.go.
	Production *ProductionConfig `json:"production,omitempty"`
}

// ProductionConfig is Config.Production: the production setup, run
// under server.AssuranceProduction and issuer.AssuranceProduction with
// what those require, rather than this binary's development wiring.
// Its stores are sqlstore's and fapigo/sqlstore's, in one SQLite file,
// with every record sealed; its access token signing key is loaded from
// here; its proof types are jwt proofs carrying a key attestation
// (haip.RecommendedIssuerConfig), with no attestation proof type; and
// key attestations are trusted by their x5c chain
// (KeyAttestationConfig.TrustAnchorPEM, required here) with their
// status checked, as Wallet Attestations' are. It is still a test
// harness: the database is a fresh file each run, and its keys come
// from this configuration.
type ProductionConfig struct {
	// DatabasePath is the SQLite file the stores keep their records in,
	// created when absent.
	DatabasePath string `json:"database_path"`

	// SealingKey is the 32-byte AES-256-GCM key, base64-encoded, every
	// store seals its records with (sealing.AESGCMSealer).
	SealingKey string `json:"sealing_key"`

	// AccessTokenSigningKeyPEM is the Authorization Server's access
	// token signing key: a P-256 private key, PEM-encoded.
	AccessTokenSigningKeyPEM string `json:"access_token_signing_key_pem"`
}

// validateProduction checks Production, when set, holds what the
// production setup needs.
func validateProduction(cfg Config) error {
	p := cfg.Production
	if p == nil {
		return nil
	}
	if p.DatabasePath == "" || p.SealingKey == "" || p.AccessTokenSigningKeyPEM == "" {
		return fmt.Errorf("config: production.database_path, production.sealing_key and production.access_token_signing_key_pem are all required when production is present")
	}
	if cfg.KeyAttestation == nil || cfg.KeyAttestation.TrustAnchorPEM == "" {
		return fmt.Errorf("config: key_attestation.trust_anchor_pem is required when production is present: its jwt proofs carry key attestations, trusted by their x5c chain")
	}
	return nil
}

// usesAuthorizationDetails reports whether any token carries
// openid_credential authorization_details: a pre-authorized code's
// (Offers), or an authorization code's (AuthorizationDetails).
func (c Config) usesAuthorizationDetails() bool { return c.Offers != nil || c.AuthorizationDetails }

// OffersConfig is Config.Offers.
type OffersConfig struct {
	// ListenAddr is the offer-minting listener's address: plain HTTP,
	// and so loopback only (loadConfig refuses any other host). Anyone
	// who can reach it can mint a redeemable offer.
	ListenAddr string `json:"listen_addr"`
}

// validateOffers checks Offers, when set, listens on loopback only.
func validateOffers(o *OffersConfig) error {
	if o == nil {
		return nil
	}
	host, _, err := net.SplitHostPort(o.ListenAddr)
	if err != nil {
		return fmt.Errorf("config: offers.listen_addr: %w", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("config: offers.listen_addr must be a loopback IP address and port, not %q: it mints offers for anyone who reaches it", o.ListenAddr)
	}
	return nil
}

// ConfigClient is Config.Client's own shape: everything needed to
// register one storage.ClientAuthMethodAttestation-authenticated
// client (HAIP §4.4.1's own Wallet Attestation requirement).
// ExpectedAttesterIssuer names who signs a valid Client Attestation
// JWT's own "iss" claim. How that attester's signing key is trusted is
// exactly one of:
//
//   - AttesterTrustAnchorsPEM: CA certificate(s) the Client Attestation
//     JWT's own "x5c" chain must verify against (HAIP 1.0 §4.4.1;
//     fapigo/server's X5CAttesterChain), from a leaf naming
//     ExpectedAttesterIssuer as a URI SAN (AttesterIssuerInCertificate)
//     — "kid" plays no part;
//   - AttesterJWKS: the attester's public key(s), looked up by "kid"
//     (fapigo/server's RegisteredAttesterKeys) — "x5c" is ignored.
//
// fapigo/server's attester trust strategy is server-wide, so Client and
// Client2 must use the same one.
//
// ApplicationType is "web" (the default, when empty) or "native": a
// native client may register a native app's redirect URIs (RFC 8252),
// such as a private-use URI scheme, com.example.wallet:/callback or
// com.example.wallet://callback (storage.ApplicationTypeNative).
type ConfigClient struct {
	ID                      string          `json:"id"`
	ApplicationType         string          `json:"application_type,omitempty"`
	RedirectURIs            []string        `json:"redirect_uris"`
	ExpectedAttesterIssuer  string          `json:"expected_attester_issuer"`
	AttesterTrustAnchorsPEM string          `json:"attester_trust_anchors_pem,omitempty"`
	AttesterJWKS            json.RawMessage `json:"attester_jwks,omitempty"`
}

// applicationType is c's storage.ApplicationType, or an error for a
// value ApplicationType doesn't take.
func (c ConfigClient) applicationType() (storage.ApplicationType, error) {
	switch c.ApplicationType {
	case "", "web":
		return storage.ApplicationTypeWeb, nil
	case "native":
		return storage.ApplicationTypeNative, nil
	}
	return 0, fmt.Errorf("application_type %q isn't web or native", c.ApplicationType)
}

// usesAttesterTrustAnchors reports whether c trusts its attester by
// certificate chain rather than registered keys.
func (c ConfigClient) usesAttesterTrustAnchors() bool { return c.AttesterTrustAnchorsPEM != "" }

// validateClients checks client, and client2 when present: each valid,
// and both trusting their attester the same way.
func validateClients(cfg Config) error {
	if err := validateConfigClient("client", cfg.Client); err != nil {
		return err
	}
	if cfg.Client2 == nil {
		return nil
	}
	if err := validateConfigClient("client2", *cfg.Client2); err != nil {
		return err
	}
	if cfg.Client2.usesAttesterTrustAnchors() != cfg.Client.usesAttesterTrustAnchors() {
		return fmt.Errorf("config: client and client2 must both use attester_trust_anchors_pem, or both attester_jwks")
	}
	return nil
}

// validateMdoc checks the mdoc configuration, when present.
func validateMdoc(cfg Config) error {
	m := cfg.Mdoc
	if m == nil {
		return nil
	}
	if m.CredentialConfigurationID == "" || m.DocType == "" || m.Namespace == "" || len(m.Claims) == 0 || m.Scope == "" {
		return fmt.Errorf("config: mdoc.credential_configuration_id, mdoc.doctype, mdoc.namespace, mdoc.claims and mdoc.scope are all required when mdoc is present")
	}
	if m.CredentialConfigurationID == cfg.CredentialConfigurationID {
		return fmt.Errorf("config: mdoc.credential_configuration_id must differ from the top-level credential_configuration_id")
	}
	if (m.CRLPEM == "") != (m.CRLListenAddr == "") {
		return fmt.Errorf("config: mdoc.crl_pem and mdoc.crl_listen_addr must be set together")
	}
	return nil
}

// mdocCRL is Mdoc's CRL in DER, or nil when none is configured.
func (c Config) mdocCRL() ([]byte, error) {
	if c.Mdoc == nil || c.Mdoc.CRLPEM == "" {
		return nil, nil
	}
	der, err := conformancecert.ParseCRLPEM(c.Mdoc.CRLPEM)
	if err != nil {
		return nil, fmt.Errorf("mdoc.crl_pem: %w", err)
	}
	return der, nil
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
	if err := validateClients(cfg); err != nil {
		return Config{}, err
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
	if err := validateMdoc(cfg); err != nil {
		return Config{}, err
	}
	if err := validateOffers(cfg.Offers); err != nil {
		return Config{}, err
	}
	if ka := cfg.KeyAttestation; ka != nil && (len(ka.TrustedJWK) == 0) == (ka.TrustAnchorPEM == "") {
		return Config{}, fmt.Errorf("config: exactly one of key_attestation.trusted_jwk and key_attestation.trust_anchor_pem is required when key_attestation is present")
	}
	if err := validateProduction(cfg); err != nil {
		return Config{}, err
	}
	if err := validateStatusLists(cfg); err != nil {
		return Config{}, err
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
	if c.ID == "" || len(c.RedirectURIs) == 0 || c.ExpectedAttesterIssuer == "" {
		return fmt.Errorf("config: %s.id, %s.redirect_uris and %s.expected_attester_issuer are all required", field, field, field)
	}
	if _, err := c.applicationType(); err != nil {
		return fmt.Errorf("config: %s.%w", field, err)
	}
	attesterJWKSEmpty := len(c.AttesterJWKS) == 0 || string(c.AttesterJWKS) == "null"
	if c.usesAttesterTrustAnchors() == !attesterJWKSEmpty {
		return fmt.Errorf("config: exactly one of %s.attester_trust_anchors_pem and %s.attester_jwks is required", field, field)
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

// mdocSignerKeyAndCert parses Mdoc's own dedicated Document Signer
// identity (conformanceconfig.MdocConfig.SignerKeyPEM/CertificatePEM)
// — ok is false when Mdoc is nil or those fields are empty, in which
// case the caller should fall back to the shared issuer identity (see
// MdocConfig's own doc comment).
func (c Config) mdocSignerKeyAndCert() (key *ecdsa.PrivateKey, cert *x509.Certificate, ok bool, err error) {
	if c.Mdoc == nil || c.Mdoc.SignerKeyPEM == "" {
		return nil, nil, false, nil
	}
	key, err = conformancecert.ParseECPrivateKeyPEM(c.Mdoc.SignerKeyPEM)
	if err != nil {
		return nil, nil, false, fmt.Errorf("mdoc.signer_key_pem: %w", err)
	}
	cert, err = conformancecert.ParseCertificatePEM(c.Mdoc.CertificatePEM)
	if err != nil {
		return nil, nil, false, fmt.Errorf("mdoc.certificate_pem: %w", err)
	}
	return key, cert, true, nil
}

func (c Config) issuerURL() (fapi.URL, error) {
	return fapi.ParseIssuerURL(c.Issuer)
}
