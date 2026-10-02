package walletflow

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/idfoundry/fapigo/client"
	"github.com/idfoundry/fapigo/fapihttp"

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
}

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
	return &Wallet{cfg: cfg, deps: deps, core: core}, nil
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

// DeleteCredential deletes the credential id names, and its holder key.
func (w *Wallet) DeleteCredential(ctx context.Context, id string) error {
	c, err := w.deps.Credentials.Get(ctx, id)
	if err != nil {
		return fmt.Errorf("walletflow: delete credential: %w", err)
	}
	if err := w.deps.Credentials.Delete(ctx, id); err != nil {
		return fmt.Errorf("walletflow: delete credential: %w", err)
	}
	if err := w.deps.Keys.DeleteKey(ctx, c.HolderKeyID); err != nil {
		return fmt.Errorf("walletflow: delete credential's holder key: %w", err)
	}
	return nil
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
	return nil
}
