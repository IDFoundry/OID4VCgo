// Package walletapp is the passport-vdc demo wallet: given a Credential
// Offer, it receives every offered credential through oid4vcgo's
// walletflow — the issuer's discovery, a Wallet Attestation from the demo
// Wallet Provider, the HAIP Authorization Code flow (PAR, PKCE, DPoP) or
// the pre-authorized code with a PIN, and each credential bound to a
// fresh holder key that the Wallet Provider attests in a Key Attestation
// — and presents them through walletflow too.
//
// It is a demo, not a secure wallet: holder keys are ordinary in-memory
// keys, stored next to the credentials (a real wallet keeps them in
// secure hardware). It never holds the Wallet Provider's key: it asks the
// provider's service for each attestation (walletprovider.Client).
package walletapp

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// Config configures a demo wallet.
type Config struct {
	// ClientID and RedirectURI must match the issuer's registration of
	// the demo wallet.
	ClientID    string
	RedirectURI string

	// Provider attests this wallet instance and its holder keys: a
	// walletprovider.Client calling the demo Wallet Provider's service.
	Provider Attester

	// IssuerRoots are the trust anchors for issuer certificates: every
	// received credential must be signed by a certificate chaining to
	// one of them, or it's refused.
	IssuerRoots *x509.CertPool

	// HTTP makes every request; nil means a client with a 10 s timeout.
	HTTP *http.Client

	// OnPending, if set, is told when Receive starts waiting for a
	// credential the issuer deferred.
	OnPending func(*Pending)
}

// Attester is the Wallet Provider, as the wallet asks it for
// attestations. walletprovider.Client implements it.
type Attester = walletflow.WalletProvider

// Approver completes the authorization step: it sends the holder's user
// agent to authorizationURL and returns the redirect back to
// RedirectURI. The flow's session stays with the wallet, which completes
// only the callback for the flow it began.
type Approver interface {
	Approve(ctx context.Context, authorizationURL string) (Callback, error)
}

// LoopbackApprover is an Approver that receives the redirect on a
// loopback port it listens on before the authorization begins, so that
// the wallet can send that port in the request (RFC 8252 §7.3).
type LoopbackApprover interface {
	Approver
	Listen(ctx context.Context) (LoopbackListener, error)
}

// LoopbackListener is a LoopbackApprover's listener for one
// authorization.
type LoopbackListener interface {
	// RedirectPort is the port to send in the authorization request, or 0
	// to send RedirectURI as configured.
	RedirectPort() uint16
	Approve(ctx context.Context, authorizationURL string) (Callback, error)
	Close() error
}

// Callback is the authorization redirect back to RedirectURI.
type Callback struct {
	// Query is the redirect's raw query.
	Query string
}

// Received is one credential the wallet obtained.
type Received struct {
	ConfigurationID string
	Format          string
	// DocType is the mdoc doctype, for mso_mdoc credentials.
	DocType string
	// Credential is the issued credential as the issuer returned it:
	// a compact SD-JWT VC, or base64url-encoded mdoc IssuerSigned CBOR.
	Credential string
	// HolderKey is the key the credential is bound to — needed to
	// present it later.
	HolderKey *ecdsa.PrivateKey
}

const httpTimeout = 10 * time.Second

// Receive redeems the Credential Offer at offerURI and returns every
// credential it offered. A credential the issuer defers is polled until
// it's issued — Config.OnPending is told when one is — or refused with
// ErrDenied; ctx bounds the wait.
func Receive(ctx context.Context, cfg Config, offerURI string, approver Approver) ([]Received, error) {
	received, pending, err := ReceiveDeferrable(ctx, cfg, offerURI, approver)
	if err != nil {
		return nil, err
	}
	for _, p := range pending {
		if cfg.OnPending != nil {
			cfg.OnPending(p)
		}
		r, err := p.Wait(ctx)
		if err != nil {
			return nil, err
		}
		received = append(received, r)
	}
	return received, nil
}

// ReceiveDeferrable is Receive without the wait: a credential the issuer
// defers comes back as a Pending to poll later, in the same process (it
// holds the access token).
func ReceiveDeferrable(ctx context.Context, cfg Config, offerURI string, approver Approver) ([]Received, []*Pending, error) {
	if cfg.Provider == nil || cfg.IssuerRoots == nil || cfg.ClientID == "" || cfg.RedirectURI == "" || approver == nil {
		return nil, nil, errors.New("walletapp: ClientID, RedirectURI, Provider, IssuerRoots and an Approver are required")
	}
	keys := newSoftwareKeys()
	w, err := walletflow.New(walletflow.Config{
		ClientID: cfg.ClientID, RedirectURI: cfg.RedirectURI, IssuerRoots: cfg.IssuerRoots, Development: true,
		// One copy: this wallet's store keeps one credential per file,
		// with one software key.
		BatchSize: 1,
	}, walletflow.Dependencies{
		Keys: keys, Credentials: walletflow.NewMemoryCredentialStore(), Provider: cfg.Provider, HTTP: httpClient(cfg.HTTP),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: %w", err)
	}
	s, err := w.StartIssuance(ctx, offerURI)
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: %w", err)
	}
	keepOpen := false
	defer func() {
		if !keepOpen {
			_ = s.Close(ctx)
		}
	}()
	if err := authorize(ctx, s, approver); err != nil {
		return nil, nil, err
	}
	result, err := s.RequestCredentials(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("walletapp: %w", err)
	}
	received := make([]Received, 0, len(result.Credentials))
	for _, c := range result.Credentials {
		received = append(received, keys.received(c))
	}
	if len(result.Deferred) == 0 {
		return received, nil, nil
	}
	// The issuance stays open, for its access token, until every
	// deferred credential is settled.
	keepOpen = true
	return received, newPendings(s, keys, result.Deferred), nil
}

// authorize runs the offer's grant: the issuer's authorization page
// through approver, or the pre-authorized code with the PIN approver
// supplies.
func authorize(ctx context.Context, s *walletflow.Issuance, approver Approver) error {
	offer := s.Offer()
	if offer.Grant == walletflow.GrantPreAuthorizedCode {
		var pin string
		if offer.TxCode != nil {
			pa, ok := approver.(PINApprover)
			if !ok {
				return errors.New("walletapp: the offer needs a PIN, and nothing can supply one")
			}
			var err error
			if pin, err = pa.PIN(ctx, *offer.TxCode); err != nil {
				return err
			}
		}
		if err := s.RedeemPreAuthorizedCode(ctx, pin); err != nil {
			return fmt.Errorf("walletapp: %w", err)
		}
		return nil
	}
	approve := approver.Approve
	var opts walletflow.AuthorizationOptions
	if la, ok := approver.(LoopbackApprover); ok {
		l, err := la.Listen(ctx)
		if err != nil {
			return fmt.Errorf("walletapp: authorization: %w", err)
		}
		defer func() { _ = l.Close() }()
		opts.RedirectPort = l.RedirectPort()
		approve = l.Approve
	}
	authURL, err := s.BeginAuthorizationWith(ctx, opts)
	if err != nil {
		return fmt.Errorf("walletapp: %w", err)
	}
	cb, err := approve(ctx, authURL)
	if err != nil {
		return fmt.Errorf("walletapp: authorization: %w", err)
	}
	if err := s.CompleteAuthorization(ctx, cb.Query); err != nil {
		return fmt.Errorf("walletapp: %w", err)
	}
	return nil
}

func httpClient(c *http.Client) *http.Client {
	if c == nil {
		return &http.Client{Timeout: httpTimeout}
	}
	return c
}
