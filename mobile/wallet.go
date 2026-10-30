package mobile

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/idfoundry/oid4vcgo/certrevocation"
	"github.com/idfoundry/oid4vcgo/credential/mdoc"
	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// config is NewWallet's JSON configuration.
type config struct {
	// ClientID and RedirectURI: the wallet's registration with
	// Authorization Servers. RedirectURI is a private-use URI scheme in
	// reverse.domain:/path form or loopback http
	// (walletflow.Config.RedirectURI).
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	// IssuerRoots and VerifierRoots are PEM certificates: the trust
	// anchors for issuers' credentials and Verifiers' requests.
	IssuerRoots   string `json:"issuer_roots"`
	VerifierRoots string `json:"verifier_roots"`
	// RegistrarRoots are PEM certificates: the registrars whose
	// registrations of Verifiers the wallet checks
	// (walletflow.Config.RegistrarRoots). Unset, they're ignored.
	RegistrarRoots string `json:"registrar_roots,omitempty"`
	// MdocReaderRoots are PEM certificates: the mdoc readers recognized
	// when one signs an org-iso-mdoc request
	// (walletflow.Config.MdocReaderRoots). Unset, every request is shown
	// by its origin.
	MdocReaderRoots string `json:"mdoc_reader_roots,omitempty"`
	// MdocReaderRequireEKU recognizes only reader certificates with the
	// ISO/IEC 18013-5 reader authentication extended key usage
	// (mdocdcapi.RequireReaderAuthenticationEKU), and
	// RequireTrustedMdocReader refuses a request no recognized reader
	// signed (walletflow.Config.RequireTrustedMdocReader).
	MdocReaderRequireEKU bool `json:"mdoc_reader_require_eku,omitempty"`
	// VerifierRequireEKU, RegistrarRequireEKU and IssuerRequireEKU,
	// dotted object identifiers, recognize only certificates under
	// VerifierRoots, RegistrarRoots and IssuerRoots with that extended
	// key usage, the one an ecosystem marks its verifiers', registrars'
	// or issuers' certificates with. Outside development, each is
	// required (MdocReaderRequireEKU for MdocReaderRoots) when its roots
	// share a trust anchor with another role's, which would otherwise
	// take that role's certificates for its own.
	VerifierRequireEKU  string `json:"verifier_require_eku,omitempty"`
	RegistrarRequireEKU string `json:"registrar_require_eku,omitempty"`
	IssuerRequireEKU    string `json:"issuer_require_eku,omitempty"`
	// MdocIssuerRoots are PEM certificates: the IACAs whose mdocs the
	// wallet receives, in place of IssuerRoots
	// (walletflow.Config.MdocIssuerRoots), and MdocIssuerRootsByDocType
	// each document type's own (walletflow.Config.MdocIssuerRootsByDocType).
	// MdocIssuerRequireEKU, a dotted object identifier, recognizes only
	// document signer certificates with that extended key usage, in
	// place of IssuerRequireEKU (walletflow.Config.MdocIssuerLeafPolicy).
	MdocIssuerRoots          string            `json:"mdoc_issuer_roots,omitempty"`
	MdocIssuerRootsByDocType map[string]string `json:"mdoc_issuer_roots_by_doctype,omitempty"`
	MdocIssuerRequireEKU     string            `json:"mdoc_issuer_require_eku,omitempty"`
	// AcceptMDLSignerWithoutEKU also accepts a document signer
	// certificate with no extended key usage extension, which the
	// default check refuses for lacking the mDL document signer's
	// (mdoc.LenientDocumentSignerPolicy), for issuers whose document
	// signers have none. It can't be set with MdocIssuerRequireEKU, or
	// with IssuerRequireEKU unless MdocIssuerRoots is set, as either
	// already decides which document signers are accepted.
	AcceptMDLSignerWithoutEKU bool `json:"accept_mdl_signer_without_eku,omitempty"`
	// IssuerMetadataRequireEKU recognizes only issuer metadata signed
	// by a certificate under IssuerMetadataRoots with this extended key
	// usage (walletflow.Config.IssuerMetadataLeafPolicy).
	IssuerMetadataRequireEKU string `json:"issuer_metadata_require_eku,omitempty"`
	RequireTrustedMdocReader bool   `json:"require_trusted_mdoc_reader,omitempty"`
	// RequireSignedDCAPIRequests refuses an unsigned OpenID4VP request
	// over the Digital Credentials API, as untrusted_verifier
	// (walletflow.Config.RequireSignedDCAPIRequests).
	RequireSignedDCAPIRequests bool `json:"require_signed_dcapi_requests,omitempty"`
	// RequireIssuerName refuses a received SD-JWT VC whose iss its
	// signing certificate doesn't name (walletflow.Config.RequireIssuerName).
	RequireIssuerName bool `json:"require_issuer_name,omitempty"`
	// AllowForeignIss receives an SD-JWT VC whose iss isn't the
	// credential_issuer it was requested from, which is refused by
	// default (walletflow.Config.AllowForeignIss).
	AllowForeignIss bool `json:"allow_foreign_iss,omitempty"`
	// IssuerMetadataRoots are PEM certificates: the trust anchors for
	// signed Credential Issuer Metadata. With them, signed metadata is
	// asked for and verified; RequireSignedIssuerMetadata refuses an
	// issuer without it, RequireIssuerMetadataName one whose metadata's
	// certificate doesn't name it, and MaxIssuerMetadataAgeSeconds
	// metadata signed longer ago (walletflow.Config).
	IssuerMetadataRoots         string `json:"issuer_metadata_roots,omitempty"`
	RequireSignedIssuerMetadata bool   `json:"require_signed_issuer_metadata,omitempty"`
	RequireIssuerMetadataName   bool   `json:"require_issuer_metadata_name,omitempty"`
	MaxIssuerMetadataAgeSeconds int64  `json:"max_issuer_metadata_age_seconds,omitempty"`
	// Development relaxes what production requires, for a wallet talking to
	// services on a development machine. Never ship an app with it set. It
	// lets issuers, Authorization Servers, Verifiers and status lists be on
	// loopback addresses, over http there too; makes requests through an
	// ordinary HTTPS client, which reaches private network addresses,
	// instead of the hardened one (trusting development_roots too, when
	// set); requires no revocation choice for a trust role, so a role in
	// neither revocation nor no_revocation_check is checked for nothing;
	// skips the check that different roles' roots share no anchor; and
	// skips the production checks on receiving credentials: durable stores
	// and keys, and the random source (walletflow.Config.Development).
	Development bool `json:"development"`
	// IssuanceProfile is "openid4vci" (the default) or "haip"
	// (walletflow.Config.IssuanceProfile).
	IssuanceProfile string `json:"issuance_profile,omitempty"`
	// DevelopmentRoots are PEM certificates the wallet's HTTPS requests
	// trust besides the system's: a development service's own CA, where
	// the platform's trust store can't be given it (Go on Android reads
	// only the system's CA files). Only with Development.
	DevelopmentRoots string `json:"development_roots,omitempty"`
	// TLSPins pins hosts' certificates for the wallet's HTTPS requests:
	// host (a name, or "*." and one, matching a label below it) → base64
	// SHA-256 digests of a certificate's SubjectPublicKeyInfo, one of
	// which a certificate in the verified chain must have
	// (walletflow.TLSPins). A mismatch fails the request as tls_pin.
	TLSPins map[string][]string `json:"tls_pins,omitempty"`
	// StatusIssuers are the Status Issuers that may sign a credential
	// issuer's status lists on its behalf: issuer → Status Issuer
	// identifiers (walletflow.Config.StatusIssuers).
	StatusIssuers map[string][]string `json:"status_issuers,omitempty"`
	// Locales are the holder's preferred languages (BCP 47, most
	// preferred first), for issuers' display metadata.
	Locales []string `json:"locales,omitempty"`
	// BatchSize is how many copies of each credential to request when an
	// issuer offers batches; 0 means walletflow.DefaultBatchSize.
	BatchSize int `json:"batch_size,omitempty"`
	// RequestRefresh asks Authorization Servers for a refresh token
	// (walletflow.Config.RequestRefresh), so RefreshCredential can
	// replace a credential's copies later without the holder.
	RequestRefresh bool `json:"request_refresh,omitempty"`
	// CopyPolicy is which copy of a credential a presentation uses:
	// "per_presentation" (the default) or "per_verifier"
	// (walletflow.Config.CopyPolicy).
	CopyPolicy string `json:"copy_policy,omitempty"`
	// ProximityDeviceAuth is how an in-person response authenticates the
	// mdoc: "signature" (the default) or "mac_preferred", deviceMac
	// where the KeyAgreement (SetKeyAgreement) can agree with the holder
	// key (walletflow.Config.ProximityDeviceAuth).
	ProximityDeviceAuth string `json:"proximity_device_auth,omitempty"`
	// CRLs are PEM "X509 CRL" blocks: the Certificate Revocation Lists
	// the roles Revocation names are checked against, replaced later by
	// SetCRLs. Revocation names the trust roles whose certificate chains
	// must pass a CRL check ("issuer", "issuer_metadata", "registrar",
	// "mdoc_reader", "verifier", "status"; walletflow.Config's
	// *Revocation fields and wallet.X5CVerifierRoots.Revocation). A
	// role named fails closed for any CA it has no current CRL from,
	// until SetCRLs supplies one. NoRevocationCheck names the roles that
	// decline checking revocation (certrevocation.NoCheck). Outside
	// development, each role whose roots are set must be named in one
	// of the two; a role can't be in both. In development, a role in
	// neither checks no revocation.
	CRLs              string   `json:"crls,omitempty"`
	Revocation        []string `json:"revocation,omitempty"`
	NoRevocationCheck []string `json:"no_revocation_check,omitempty"`
	// CRLIssuers are PEM certificates of the CAs that issued
	// certificates pinned in the roots (a leaf in verifier_roots, say),
	// for a role Revocation names: a pinned certificate is checked
	// against its CA's CRL, verified with the CA's certificate from here
	// (certrevocation.CRLs.Issuers). They aren't trust anchors. Without
	// its CA here, a pinned certificate that isn't self-signed is
	// refused, failing closed.
	CRLIssuers string `json:"crl_issuers,omitempty"`
}

// proximityDeviceAuth is the walletflow.ProximityDeviceAuth name names.
func proximityDeviceAuth(name string) (walletflow.ProximityDeviceAuth, error) {
	switch name {
	case "", "signature":
		return walletflow.ProximityDeviceSignature, nil
	case "mac_preferred":
		return walletflow.ProximityDeviceMACPreferred, nil
	}
	return 0, fmt.Errorf("proximity_device_auth %q: want signature or mac_preferred", name)
}

// copyPolicy is the walletflow.CopyPolicy name names.
func copyPolicy(name string) (walletflow.CopyPolicy, error) {
	switch name {
	case "", "per_presentation":
		return walletflow.CopyPerPresentation, nil
	case "per_verifier":
		return walletflow.CopyPerVerifier, nil
	}
	return 0, fmt.Errorf("copy_policy %q: want per_presentation or per_verifier", name)
}

// testHTTP, when set (by the mobiletest build), is the HTTP client every
// Wallet made afterwards uses: one trusting the in-process test issuer's
// certificate.
var testHTTP atomic.Pointer[http.Client]

// Wallet is a holder's wallet: walletflow over the app's KeyStore,
// CredentialStore and WalletProvider.
type Wallet struct {
	w    *walletflow.Wallet
	keys KeyStore
	ka   *agreement
	// crls are the lists the "revocation" roles check against.
	crls *crlSet

	// refusalRedirect is the redirect_uri the Verifier answered the
	// latest refused request with (TakeRefusalRedirect).
	refusalMu       sync.Mutex
	refusalRedirect string
}

// SetKeyAgreement gives the wallet ka, to agree keys with its holder
// keys for deviceMac when "proximity_device_auth" is "mac_preferred";
// nil removes it, and the wallet signs. It's separate from the KeyStore
// so a KeyStore stays as it was, and a platform that can't agree keys
// needn't implement it.
func (w *Wallet) SetKeyAgreement(ka KeyAgreement) {
	if ka == nil {
		w.ka.ka.Store(nil)
		return
	}
	w.ka.ka.Store(&ka)
}

// NewWallet returns a Wallet configured by configJSON:
//
//	{"client_id": "…", "redirect_uri": "…",
//	 "issuer_roots": "<PEM>", "verifier_roots": "<PEM>",
//	 "development": false, "request_refresh": false,
//	 "copy_policy": "per_presentation", "issuance_profile": "openid4vci"}
//
// issuer_roots is needed to receive credentials, and verifier_roots to
// present them. provider may be nil: the wallet then receives
// credentials only from issuers that ask for no attestation, and needs
// no client_id or, for pre-authorized codes, redirect_uri.
// issuance_profile is "openid4vci", the default, following the issuer's
// metadata, or "haip", also refusing issuers outside HAIP 1.0, which
// needs a provider and client_id.
func NewWallet(configJSON string, keys KeyStore, credentials CredentialStore, provider WalletProvider) (*Wallet, error) {
	var cfg config
	// A misspelled key, a require_* option say, is refused rather than
	// silently left at its default.
	if err := decodeConfig(configJSON, &cfg); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("configuration: %w", err))
	}
	if keys == nil || credentials == nil {
		return nil, newError(CodeInvalidInput, errors.New("a KeyStore and a CredentialStore are required"))
	}
	wcfg, err := walletConfig(cfg)
	if err != nil {
		return nil, err
	}
	crls, err := walletRevocation(cfg, &wcfg)
	if err != nil {
		return nil, err
	}
	ka := &agreement{}
	deps := walletflow.Dependencies{
		Keys: keyStore{ks: keys, ka: ka}, Credentials: credentialStore{credentials},
		// crypto/rand.Reader itself, which production assurance requires.
		Random: rand.Reader,
		// Pending deferred credentials, authorizations in progress and
		// refresh grants, kept beside the credentials.
		Deferred: deferredStore{credentials}, Authorizations: authorizationStore{credentials}, Grants: grantStore{credentials},
		HTTP: testHTTP.Load(), // nil: walletflow's own client
	}
	if deps.HTTP, err = walletHTTP(cfg, &wcfg, deps.HTTP); err != nil {
		return nil, err
	}
	if provider != nil {
		deps.Provider = walletProvider{provider}
	}
	w, err := walletflow.New(wcfg, deps)
	if err != nil {
		return nil, newError(CodeInvalidInput, err)
	}
	return &Wallet{w: w, keys: keys, ka: ka, crls: crls}, nil
}

// walletRevocation sets the revocation check of each role cfg's
// "revocation" names on wcfg, over a crlSet holding cfg's "crls", which
// it returns for SetCRLs, and certrevocation.NoCheck for each role its
// "no_revocation_check" names. Outside development, it refuses a role
// whose roots are set that neither names. It runs after walletConfig,
// whose VerifierTrust it extends.
func walletRevocation(cfg config, wcfg *walletflow.Config) (*crlSet, error) {
	known := []string{revocationIssuer, revocationIssuerMetadata, revocationRegistrar,
		revocationMdocReader, revocationVerifier, revocationStatus}
	named, err := revocationRoles("revocation", cfg.Revocation, known...)
	if err != nil {
		return nil, err
	}
	declined, err := revocationRoles("no_revocation_check", cfg.NoRevocationCheck, known...)
	if err != nil {
		return nil, err
	}
	crls, err := newCRLSet(cfg.CRLs, cfg.CRLIssuers)
	if err != nil {
		return nil, err
	}
	vt, isX5C := wcfg.VerifierTrust.(wallet.X5CVerifierRoots)
	issuerKeys := "issuer_roots, mdoc_issuer_roots or mdoc_issuer_roots_by_doctype"
	receives := wcfg.IssuerRoots != nil || wcfg.MdocIssuerRoots != nil || len(wcfg.MdocIssuerRootsByDocType) > 0
	for _, r := range []struct {
		role  string
		keys  string
		inUse bool
		field *certrevocation.Checker
	}{
		{revocationIssuer, issuerKeys, receives, &wcfg.IssuerRevocation},
		{revocationStatus, issuerKeys, receives, &wcfg.StatusRevocation},
		{revocationIssuerMetadata, "issuer_metadata_roots", wcfg.IssuerMetadataRoots != nil, &wcfg.IssuerMetadataRevocation},
		{revocationRegistrar, "registrar_roots", wcfg.RegistrarRoots != nil, &wcfg.RegistrarRevocation},
		{revocationMdocReader, "mdoc_reader_roots", wcfg.MdocReaderRoots != nil, &wcfg.MdocReaderRevocation},
		{revocationVerifier, "verifier_roots", isX5C, &vt.Revocation},
	} {
		when := "outside development"
		if cfg.Development {
			when = ""
		}
		checker, err := revocationChoice(r.role, r.keys, r.inUse, named, declined, when, crls)
		if err != nil {
			return nil, err
		}
		if checker != nil {
			*r.field = checker
		}
	}
	if isX5C {
		wcfg.VerifierTrust = vt
	}
	return crls, nil
}

// SetCRLs replaces the Certificate Revocation Lists the configuration's
// "revocation" roles are checked against with pemText's "X509 CRL"
// blocks, for every check from now on: call it whenever fresh lists are
// fetched, before the current ones' nextUpdate passes. Text holding
// anything else, or a list that doesn't parse, is invalid_input, and the
// lists are left as they were. Empty text removes them all, and a role
// checked then fails closed.
func (w *Wallet) SetCRLs(pemText string) error {
	if err := w.crls.set(pemText); err != nil {
		return newError(CodeInvalidInput, fmt.Errorf("crls: %w", err))
	}
	return nil
}

// walletConfig is cfg as walletflow's Config, its HTTP settings aside
// (walletHTTP).
func walletConfig(cfg config) (walletflow.Config, error) {
	wcfg := walletflow.Config{
		ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, Development: cfg.Development, Locales: cfg.Locales,
		BatchSize: cfg.BatchSize, RequestRefresh: cfg.RequestRefresh,
		RequireTrustedMdocReader: cfg.RequireTrustedMdocReader, RequireSignedDCAPIRequests: cfg.RequireSignedDCAPIRequests,
	}
	switch cfg.IssuanceProfile {
	case "", "openid4vci":
	case "haip":
		wcfg.IssuanceProfile = walletflow.ProfileHAIP
	default:
		return walletflow.Config{}, newError(CodeInvalidInput, fmt.Errorf("issuance_profile %q: want \"openid4vci\" or \"haip\"", cfg.IssuanceProfile))
	}
	policy, err := copyPolicy(cfg.CopyPolicy)
	if err != nil {
		return walletflow.Config{}, newError(CodeInvalidInput, err)
	}
	wcfg.CopyPolicy = policy
	if wcfg.IssuerRoots, err = optionalCertPool("issuer_roots", cfg.IssuerRoots); err != nil {
		return walletflow.Config{}, err
	}
	wcfg.StatusIssuers = cfg.StatusIssuers
	wcfg.RequireIssuerName, wcfg.AllowForeignIss = cfg.RequireIssuerName, cfg.AllowForeignIss
	if wcfg.IssuerMetadataRoots, err = optionalCertPool("issuer_metadata_roots", cfg.IssuerMetadataRoots); err != nil {
		return walletflow.Config{}, err
	}
	if (cfg.RequireSignedIssuerMetadata || cfg.RequireIssuerMetadataName) && wcfg.IssuerMetadataRoots == nil {
		return walletflow.Config{}, newError(CodeInvalidInput, errors.New("require_signed_issuer_metadata and require_issuer_metadata_name need issuer_metadata_roots"))
	}
	if cfg.MaxIssuerMetadataAgeSeconds < 0 {
		return walletflow.Config{}, newError(CodeInvalidInput, errors.New("max_issuer_metadata_age_seconds must not be negative"))
	}
	wcfg.RequireSignedIssuerMetadata, wcfg.RequireIssuerMetadataName = cfg.RequireSignedIssuerMetadata, cfg.RequireIssuerMetadataName
	wcfg.MaxIssuerMetadataAge = time.Duration(cfg.MaxIssuerMetadataAgeSeconds) * time.Second
	verifierRoots, err := optionalCertPool("verifier_roots", cfg.VerifierRoots)
	if err != nil {
		return walletflow.Config{}, err
	}
	if err := checkRoleRoots(cfg); err != nil {
		return walletflow.Config{}, err
	}
	verifierPolicy, err := roleEKU("verifier_require_eku", cfg.VerifierRequireEKU)
	if err != nil {
		return walletflow.Config{}, err
	}
	if verifierRoots != nil {
		wcfg.VerifierTrust = wallet.X5CVerifierRoots{Roots: verifierRoots, LeafPolicy: verifierPolicy}
	}
	if wcfg.IssuerMetadataLeafPolicy, err = roleEKU("issuer_metadata_require_eku", cfg.IssuerMetadataRequireEKU); err != nil {
		return walletflow.Config{}, err
	}
	if wcfg.IssuerLeafPolicy, err = roleEKU("issuer_require_eku", cfg.IssuerRequireEKU); err != nil {
		return walletflow.Config{}, err
	}
	if err := mdocIssuerTrust(cfg, &wcfg); err != nil {
		return walletflow.Config{}, err
	}
	if wcfg.RegistrarRoots, err = optionalCertPool("registrar_roots", cfg.RegistrarRoots); err != nil {
		return walletflow.Config{}, err
	}
	if wcfg.RegistrarLeafPolicy, err = roleEKU("registrar_require_eku", cfg.RegistrarRequireEKU); err != nil {
		return walletflow.Config{}, err
	}
	if wcfg.MdocReaderRoots, err = optionalCertPool("mdoc_reader_roots", cfg.MdocReaderRoots); err != nil {
		return walletflow.Config{}, err
	}
	if cfg.MdocReaderRequireEKU {
		wcfg.MdocReaderLeafPolicy = mdocdcapi.RequireReaderAuthenticationEKU
	}
	if wcfg.ProximityDeviceAuth, err = proximityDeviceAuth(cfg.ProximityDeviceAuth); err != nil {
		return walletflow.Config{}, newError(CodeInvalidInput, err)
	}
	return wcfg, nil
}

// mdocIssuerTrust sets wcfg's mdoc-specific issuer trust from cfg's
// mdoc_issuer_roots, mdoc_issuer_roots_by_doctype and
// mdoc_issuer_require_eku.
func mdocIssuerTrust(cfg config, wcfg *walletflow.Config) error {
	var err error
	if wcfg.MdocIssuerRoots, err = optionalCertPool("mdoc_issuer_roots", cfg.MdocIssuerRoots); err != nil {
		return err
	}
	if len(cfg.MdocIssuerRootsByDocType) > 0 {
		wcfg.MdocIssuerRootsByDocType = make(map[string]*x509.CertPool, len(cfg.MdocIssuerRootsByDocType))
		for docType, pemText := range cfg.MdocIssuerRootsByDocType {
			// Unlike an unset key, an empty entry names its type with no
			// roots: none of its documents are accepted.
			pool, err := optionalCertPool(fmt.Sprintf("mdoc_issuer_roots_by_doctype[%q]", docType), pemText)
			if err != nil {
				return err
			}
			wcfg.MdocIssuerRootsByDocType[docType] = pool
		}
	}
	if !cfg.AcceptMDLSignerWithoutEKU {
		wcfg.MdocIssuerLeafPolicy, err = roleEKU("mdoc_issuer_require_eku", cfg.MdocIssuerRequireEKU)
		return err
	}
	switch {
	case cfg.MdocIssuerRequireEKU != "":
		return newError(CodeInvalidInput, errors.New("accept_mdl_signer_without_eku can't be set with mdoc_issuer_require_eku, which already decides which document signers are accepted"))
	case cfg.IssuerRequireEKU != "" && cfg.MdocIssuerRoots == "":
		// Some mdocs would then chain to issuer_roots, held to
		// issuer_require_eku, which the lenient check would replace.
		return newError(CodeInvalidInput, errors.New("accept_mdl_signer_without_eku needs mdoc_issuer_roots when issuer_require_eku is set"))
	}
	wcfg.MdocIssuerLeafPolicy = mdoc.LenientDocumentSignerPolicy
	return nil
}

// optionalCertPool is the PEM certificates of the config key name as a
// pool, or nil when there are none.
func optionalCertPool(name, pemText string) (*x509.CertPool, error) {
	if pemText == "" {
		return nil, nil
	}
	pool, err := certPool(pemText)
	if err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("%s: %w", name, err))
	}
	return pool, nil
}

// walletHTTP is the HTTP client the wallet uses: client (a test one) or,
// for development_roots, a development client, pinned to cfg's
// tls_pins. nil leaves walletflow its own client, which it pins itself
// (wcfg.TLSPins).
func walletHTTP(cfg config, wcfg *walletflow.Config, client *http.Client) (*http.Client, error) {
	var err error
	if cfg.DevelopmentRoots != "" {
		if !cfg.Development {
			return nil, newError(CodeInvalidInput, errors.New("development_roots needs development"))
		}
		if client == nil {
			if client, err = developmentClient(cfg.DevelopmentRoots); err != nil {
				return nil, newError(CodeInvalidInput, fmt.Errorf("development_roots: %w", err))
			}
		}
	}
	pins := walletflow.TLSPins(cfg.TLSPins)
	if len(pins) == 0 {
		return client, nil
	}
	if err := pins.Validate(); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("tls_pins: %w", err))
	}
	// walletflow pins its own client; a development or test one is this
	// package's to pin.
	if client == nil {
		wcfg.TLSPins = pins
		return nil, nil
	}
	if client, err = withPins(client, pins); err != nil {
		return nil, newError(CodeInternal, err)
	}
	return client, nil
}

// developmentClient is an HTTP client trusting the system's CAs and
// those of pemText, as walletflow's own in development: no address
// restrictions, its timeout.
func developmentClient(pemText string) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, errors.New("no PEM certificates")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: transport, Timeout: developmentTimeout}, nil
}

// withPins is c checking pins after each TLS handshake.
func withPins(c *http.Client, pins walletflow.TLSPins) (*http.Client, error) {
	base, ok := c.Transport.(*http.Transport)
	if !ok {
		return nil, errors.New("tls_pins: the HTTP client's transport isn't an *http.Transport")
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	// After any check the client already makes, not instead of it.
	if prev := transport.TLSClientConfig.VerifyConnection; prev != nil {
		transport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if err := prev(cs); err != nil {
				return err
			}
			return pins.VerifyConnection(cs)
		}
	} else {
		transport.TLSClientConfig.VerifyConnection = pins.VerifyConnection
	}
	pinned := *c
	pinned.Transport = transport
	return &pinned, nil
}

// developmentTimeout bounds each request of developmentClient's, as
// walletflow's own client's are.
const developmentTimeout = 10 * time.Second

func certPool(pemText string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(pemText)) {
		return nil, errors.New("no PEM certificates")
	}
	return pool, nil
}

// Credentials returns {"abi", "credentials": [{"id",
// "credential_issuer", "configuration_id", "format", "vct", "doctype",
// "received_at", "holder_key_present"}]}: every credential the wallet
// holds.
func (w *Wallet) Credentials() (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	summaries := make([]credentialSummary, 0, len(creds))
	for _, c := range creds {
		s, err := w.summary(c)
		if err != nil {
			return "", err
		}
		summaries = append(summaries, s)
	}
	return marshal(struct {
		result
		Credentials []credentialSummary `json:"credentials"`
	}{result{ABIVersion}, summaries})
}

// Credential returns one credential for display: its summary with
// "claims" — an SD-JWT VC's claims, or an mdoc's namespace → element →
// value, byte strings in base64 — or not_found.
func (w *Wallet) Credential(id string) (string, error) {
	creds, err := w.w.Credentials(context.Background())
	if err != nil {
		return "", classify(err)
	}
	for _, c := range creds {
		if c.ID != id {
			continue
		}
		s, err := w.summary(c)
		if err != nil {
			return "", err
		}
		return marshal(struct {
			result
			credentialSummary
			Claims any `json:"claims"`
		}{result{ABIVersion}, s, jsonClaims(c.Claims)})
	}
	return "", newError(CodeNotFound, fmt.Errorf("no credential %q", id))
}

// summary is c's summary, with whether its holder key is still present.
func (w *Wallet) summary(c walletflow.StoredCredential) (credentialSummary, error) {
	s := summaryOf(c)
	pub, err := w.keys.PublicKey(c.HolderKeyID)
	if err != nil {
		return credentialSummary{}, newError(CodePlatform, fmt.Errorf("credential %q's holder key: %w", c.ID, err))
	}
	present := len(pub) > 0
	s.HolderKeyPresent = &present
	return s, nil
}

// HolderKeyIDs returns {"abi", "key_ids": [...]}: the IDs of the keys
// the wallet still needs — its credentials' holder keys, each pending
// deferred credential's holder and DPoP keys, and each refresh grant
// in use's wallet instance key (a grant no credential uses is forgotten,
// with its key). Every other key in the KeyStore belongs to an issuance
// or refresh in progress — or to none, left by one that never finished —
// so an app sweeping orphaned keys at launch, before any issuance or
// refresh, keeps these and may delete the rest.
func (w *Wallet) HolderKeyIDs() (string, error) {
	ids, err := w.w.KeysInUse(context.Background())
	if err != nil {
		return "", classify(err)
	}
	if ids == nil {
		ids = []string{}
	}
	return marshal(struct {
		result
		KeyIDs []string `json:"key_ids"`
	}{result{ABIVersion}, ids})
}

// CheckStatus fetches the issuer's status list for the credential
// credentialID names, checks its signature, records the credential's revocation
// status, and returns the credential's summary with it ("status":
// {"value": "valid" | "invalid" | "suspended" | "0x…" | "unknown",
// "checked_at"}). A credential without a status list is returned as it
// is, as is an expired one, whose status list isn't fetched; an mdoc
// naming an identifier list, which isn't checked, is "unknown" unless a
// status list it names too says otherwise than valid. The list
// covers many credentials, so fetching it doesn't tell the issuer which
// one is checked.
func (w *Wallet) CheckStatus(op *Operation, credentialID string) (string, error) {
	c, err := w.w.CheckStatus(op.context(), credentialID)
	if err != nil {
		return "", classify(err)
	}
	s, err := w.summary(c)
	if err != nil {
		return "", err
	}
	return marshal(struct {
		result
		credentialSummary
	}{result{ABIVersion}, s})
}

// DeleteCredential deletes the credential id names, and its holder
// keys, and its refresh grant once no other credential uses it, first
// revoking the refresh token at the Authorization Server (RFC 7009),
// best effort: a network request.
func (w *Wallet) DeleteCredential(id string) error {
	return classify(w.w.DeleteCredential(context.Background(), id))
}

// marshal returns v as JSON text.
func marshal(v any) (string, error) {
	out, err := json.Marshal(v)
	if err != nil {
		return "", newError(CodeInternal, err)
	}
	return string(out), nil
}
