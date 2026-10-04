package walletflow

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"
	"github.com/idfoundry/fapigo/keys"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// Config configures a Wallet.
type Config struct {
	// ClientID and RedirectURI are the wallet's registration with
	// Authorization Servers: the client_id its Wallet Attestations
	// name, and where the authorization code grant redirects back to.
	// REQUIRED for StartIssuance.
	ClientID    string
	RedirectURI string

	// IssuerRoots are the trust anchors for issuers: every received
	// credential must be signed by a certificate chaining to one of
	// them, or it's refused. REQUIRED for StartIssuance.
	IssuerRoots *x509.CertPool

	// VerifierTrust decides which Verifiers the wallet answers
	// (OpenID4VP 1.0 §5.9.3). REQUIRED for StartPresentation.
	VerifierTrust wallet.VerifierTrust

	// RegistrarRoots, if set, are the registrars whose registrations of
	// Verifiers the wallet checks (the registration package): a
	// request's registration, from its verifier_info, is reported with
	// what the request asks beyond it (Presentation.Registration).
	// Unset, registrations are ignored.
	RegistrarRoots *x509.CertPool

	// Locales are the holder's preferred languages (BCP 47 tags, most
	// preferred first), for the issuer's display metadata. None means
	// the issuer's entry without a locale, else its first.
	Locales []string

	// RequestRefresh asks the Authorization Server, in the authorization
	// code flow, for a refresh token (the offline_access scope), so
	// Wallet.RefreshCredential can later replace a credential's copies
	// without the holder (OpenID4VCI 1.0 §13.5). The server must allow
	// the wallet that scope, or the authorization fails with
	// invalid_scope. In the pre-authorized code flow there's no scope to
	// ask with: a refresh token the server issues anyway is kept. The
	// refresh token and the wallet instance key are then kept in
	// Dependencies.Grants; without RequestRefresh, a refresh token is
	// discarded.
	RequestRefresh bool

	// CopyPolicy decides which copy of a credential a presentation uses
	// (OpenID4VCI 1.0: "a unique Credential per presentation or per
	// Verifier"). The zero value is CopyPerPresentation.
	CopyPolicy CopyPolicy

	// BatchSize is how many copies of each credential to request when
	// the issuer offers batch issuance, each bound to its own key, so
	// each presentation can use one no Verifier has seen. It's capped at
	// the issuer's batch_size. Zero means DefaultBatchSize; 1 requests
	// one copy.
	BatchSize int

	// Development relaxes what production requires, for a wallet
	// talking to services on this machine: issuers, Authorization
	// Servers and Verifiers on loopback addresses.
	Development bool
}

// Dependencies are what the app supplies.
type Dependencies struct {
	Keys        KeyStore        // REQUIRED
	Credentials CredentialStore // REQUIRED
	Provider    WalletProvider  // REQUIRED for StartIssuance
	// Deferred keeps pending deferred credentials, so they can be polled
	// after a restart. nil means a MemoryDeferredStore.
	Deferred DeferredStore
	// Authorizations keeps the authorizations in progress, so the
	// redirect can complete one after a restart (ResumeIssuance). nil
	// means a MemoryAuthorizationStore. Receiving credentials at
	// production assurance (Config.Development false) needs a Durable
	// one, Keys that declare durable custody (keys.KeyCustodyAssurance),
	// and Random left nil or crypto/rand.Reader.
	Authorizations AuthorizationStore
	// Grants keeps refresh grants (Config.RequestRefresh). nil means a
	// MemoryGrantStore. Receiving credentials at production assurance
	// with RequestRefresh set needs a Durable one.
	Grants GrantStore

	// HTTP makes every request. nil means a client with a 10 s timeout.
	HTTP *http.Client
	// Clock returns the current time. nil means time.Now.
	Clock func() time.Time
	// Random is the source of identifiers and protocol randomness. nil
	// means crypto/rand.
	Random io.Reader
}

// Wallet is a holder's wallet. Its methods are safe for concurrent use;
// each session they start is used by one goroutine at a time.
type Wallet struct {
	cfg  Config
	deps Dependencies
	core *wallet.Wallet

	mu       sync.Mutex
	deferred map[string]*Deferred // the pending ones handed out, by ID
	liveDPoP map[string]bool      // DPoP keys open issuances hold
	// openGrants are the refresh grants open issuances hold, by ID: in
	// use until the issuance closes, however many credentials are stored
	// yet.
	openGrants map[string]bool
	authMu     sync.Mutex // serializes consuming authorizations
	// credMu serializes reading, changing and writing back a stored
	// credential: choosing and marking the copies a presentation uses,
	// recording a status, replacing a refreshed one, deleting one. It's
	// never held across a network request.
	credMu sync.Mutex
	// grantMu serializes refreshes per refresh grant (grantLocks, by
	// grant ID), held across the refresh's requests.
	grantMu    sync.Mutex
	grantLocks map[string]*sync.Mutex
}

// CopyPolicy is which copy of a credential a presentation uses.
type CopyPolicy int

const (
	// CopyPerPresentation presents a copy no Verifier has seen, every
	// time: not even the same Verifier can link two presentations by the
	// credential. Copies run out fastest. It's the default.
	CopyPerPresentation CopyPolicy = iota
	// CopyPerVerifier presents a Verifier the copy it has seen before, if
	// any, else one no Verifier has seen: Verifiers can't link
	// presentations to each other, but one Verifier can recognise a
	// returning holder. Copies last as long as there are new Verifiers.
	CopyPerVerifier
)

// DefaultBatchSize is how many copies of a credential a wallet requests
// when Config.BatchSize is zero and the issuer offers batch issuance.
const DefaultBatchSize = 5

const (
	httpTimeout      = 10 * time.Second
	maxResponseBytes = 1 << 20
)

// New returns a Wallet.
func New(cfg Config, deps Dependencies) (*Wallet, error) {
	if deps.Keys == nil || deps.Credentials == nil {
		return nil, errors.New("walletflow: Dependencies.Keys and Credentials are required")
	}
	if deps.HTTP == nil {
		deps.HTTP = &http.Client{Timeout: httpTimeout}
	}
	if deps.Clock == nil {
		deps.Clock = time.Now
	}
	if deps.Random == nil {
		deps.Random = rand.Reader
	}
	if deps.Deferred == nil {
		deps.Deferred = NewMemoryDeferredStore()
	}
	if deps.Authorizations == nil {
		deps.Authorizations = NewMemoryAuthorizationStore()
	}
	if deps.Grants == nil {
		deps.Grants = NewMemoryGrantStore()
	}
	core, err := wallet.New(wallet.Config{
		Assurance: cfg.assurance(), ProofSigningAlg: oid4vci.ES256, VerifierTrust: cfg.VerifierTrust,
		Fetch: fapihttp.Config{
			MaxResponseBytes: maxResponseBytes, RequestTimeout: httpTimeout, MaxRedirects: 2,
			AllowLoopbackHosts: cfg.Development,
		},
	}, wallet.Dependencies{HTTP: deps.HTTP, Clock: wallet.ClockFunc(deps.Clock), Random: deps.Random})
	if err != nil {
		return nil, fmt.Errorf("walletflow: %w", err)
	}
	return &Wallet{
		cfg: cfg, deps: deps, core: core, deferred: map[string]*Deferred{}, liveDPoP: map[string]bool{},
		openGrants: map[string]bool{}, grantLocks: map[string]*sync.Mutex{},
	}, nil
}

func (c Config) assurance() wallet.AssuranceLevel {
	if c.Development {
		return wallet.AssuranceDevelopment
	}
	return wallet.AssuranceProduction
}

func (c Config) clientAssurance() client.AssuranceLevel {
	if c.Development {
		return client.AssuranceDevelopment
	}
	return client.AssuranceProduction
}

// Credentials returns every credential the wallet holds.
func (w *Wallet) Credentials(ctx context.Context) ([]StoredCredential, error) {
	creds, err := w.deps.Credentials.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("walletflow: list credentials: %w", err)
	}
	return creds, nil
}

// DeleteCredential deletes the credential id names, and every copy's
// holder key. Once no other credential uses its refresh grant, the
// refresh token is revoked at the Authorization Server (RFC 7009), best
// effort and only when it has a revocation endpoint, so the issuer's
// standing grant ends with it; then the grant and its instance key are
// deleted.
func (w *Wallet) DeleteCredential(ctx context.Context, id string) error {
	c, err := w.deleteCredential(ctx, id)
	if err != nil {
		return err
	}
	if err := w.releaseUnusedGrant(ctx, c.GrantID, c.ConfigurationID); err != nil {
		return fmt.Errorf("walletflow: delete credential's refresh grant: %w", err)
	}
	return nil
}

// deleteCredential deletes the credential id names and its copies'
// keys, and returns it.
func (w *Wallet) deleteCredential(ctx context.Context, id string) (StoredCredential, error) {
	w.credMu.Lock()
	defer w.credMu.Unlock()
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	if err := w.deps.Credentials.Delete(ctx, id); err != nil {
		return StoredCredential{}, fmt.Errorf("walletflow: delete credential: %w", err)
	}
	for _, cp := range c.AllCopies() {
		if err := w.deps.Keys.DeleteKey(ctx, cp.HolderKeyID); err != nil {
			return StoredCredential{}, fmt.Errorf("walletflow: delete credential's holder key: %w", err)
		}
	}
	return c, nil
}

// checkIssuance reports what StartIssuance needs that w lacks.
func (w *Wallet) checkIssuance() error {
	switch {
	case w.cfg.ClientID == "" || w.cfg.RedirectURI == "":
		return errors.New("walletflow: Config.ClientID and Config.RedirectURI are required to receive credentials")
	case w.cfg.IssuerRoots == nil:
		return errors.New("walletflow: Config.IssuerRoots is required to receive credentials")
	case w.deps.Provider == nil:
		return errors.New("walletflow: Dependencies.Provider is required to receive credentials")
	}
	if w.cfg.Development {
		return nil
	}
	// fapigo/client's production assurance, checked here first to say
	// what to change.
	switch {
	case !w.deps.Authorizations.Durable():
		return errors.New("walletflow: receiving credentials in production needs a Durable Dependencies.Authorizations, so an authorization survives the app being suspended")
	case w.cfg.RequestRefresh && !w.deps.Grants.Durable():
		return errors.New("walletflow: refreshing credentials in production needs a Durable Dependencies.Grants, so a refresh token survives a restart")
	case !durableKeys(w.deps.Keys):
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Keys to declare durable custody (keys.KeyCustodyAssurance)")
	case w.deps.Random != rand.Reader:
		return errors.New("walletflow: receiving credentials in production needs Dependencies.Random to be nil or crypto/rand.Reader")
	}
	return nil
}

// durableKeys reports whether ks declares it keeps its keys durably.
func durableKeys(ks KeyStore) bool {
	c, ok := ks.(keys.KeyCustodyAssurance)
	return ok && c.KeyCustody().Durable
}
