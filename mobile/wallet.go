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
	"sync/atomic"
	"time"

	"github.com/idfoundry/oid4vcgo/mdocdcapi"
	"github.com/idfoundry/oid4vcgo/wallet"
	"github.com/idfoundry/oid4vcgo/walletflow"
)

// config is NewWallet's JSON configuration.
type config struct {
	// ClientID and RedirectURI: the wallet's registration with
	// Authorization Servers.
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
	MdocReaderRequireEKU     bool `json:"mdoc_reader_require_eku,omitempty"`
	RequireTrustedMdocReader bool `json:"require_trusted_mdoc_reader,omitempty"`
	// RequireSignedDCAPIRequests refuses an unsigned OpenID4VP request
	// over the Digital Credentials API, as untrusted_verifier
	// (walletflow.Config.RequireSignedDCAPIRequests).
	RequireSignedDCAPIRequests bool `json:"require_signed_dcapi_requests,omitempty"`
	// Development allows services on loopback addresses.
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
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return nil, newError(CodeInvalidInput, fmt.Errorf("configuration: %w", err))
	}
	if keys == nil || credentials == nil {
		return nil, newError(CodeInvalidInput, errors.New("a KeyStore and a CredentialStore are required"))
	}
	wcfg, err := walletConfig(cfg)
	if err != nil {
		return nil, err
	}
	deps := walletflow.Dependencies{
		Keys: keyStore{keys}, Credentials: credentialStore{credentials},
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
	return &Wallet{w: w, keys: keys}, nil
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
	verifierRoots, err := optionalCertPool("verifier_roots", cfg.VerifierRoots)
	if err != nil {
		return walletflow.Config{}, err
	}
	if verifierRoots != nil {
		wcfg.VerifierTrust = wallet.X5CVerifierRoots{Roots: verifierRoots}
	}
	if wcfg.RegistrarRoots, err = optionalCertPool("registrar_roots", cfg.RegistrarRoots); err != nil {
		return walletflow.Config{}, err
	}
	if wcfg.MdocReaderRoots, err = optionalCertPool("mdoc_reader_roots", cfg.MdocReaderRoots); err != nil {
		return walletflow.Config{}, err
	}
	if cfg.MdocReaderRequireEKU {
		wcfg.MdocReaderLeafPolicy = mdocdcapi.RequireReaderAuthenticationEKU
	}
	return wcfg, nil
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
	transport.TLSClientConfig.VerifyConnection = pins.VerifyConnection
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
// {"value": "valid" | "invalid" | "suspended" | "0x…", "checked_at"}).
// A credential without a status list is returned as it is. The list
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
