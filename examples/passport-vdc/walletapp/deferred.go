package walletapp

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	oid4vci "github.com/idfoundry/oid4vcgo"
	"github.com/idfoundry/oid4vcgo/wallet"
)

// ErrDenied is returned for a deferred credential the issuer refused
// (OID4VCI 1.0 §9.3, credential_request_denied).
var ErrDenied = errors.New("walletapp: the issuer denied the credential")

// minPollInterval is the shortest wait between polls, whatever interval
// the issuer asks for.
const minPollInterval = time.Second

// issuance is what requesting one offer's credentials shares: the
// wallet, the access token's resource client, and the issuer's metadata
// and encryption choices.
type issuance struct {
	w           *wallet.Wallet
	cfg         Config
	resource    wallet.ProtectedResourceClient
	metadata    oid4vci.Metadata
	requestEnc  *wallet.RequestEncryption
	responseEnc *wallet.ResponseEncryption
}

// accept validates the one credential result carries, bound to holder,
// and tells the issuer whether the wallet kept it (§11).
func (is issuance) accept(ctx context.Context, configID string, holder *ecdsa.PrivateKey, result wallet.CredentialResult) (Received, error) {
	if len(result.Credentials) != 1 {
		return Received{}, fmt.Errorf("walletapp: credential %q: got %d credentials, want 1", configID, len(result.Credentials))
	}
	conf := is.metadata.CredentialConfigurationsSupported[configID]
	if err := validateReceived(ctx, conf, result.Credentials[0].Credential, holder, is.cfg.IssuerRoots, time.Now()); err != nil {
		is.notify(ctx, result.NotificationID, oid4vci.NotificationEventCredentialFailure, "the credential failed the wallet's checks")
		return Received{}, fmt.Errorf("walletapp: credential %q is invalid: %w", configID, err)
	}
	is.notify(ctx, result.NotificationID, oid4vci.NotificationEventCredentialAccepted, "")
	return Received{
		ConfigurationID: configID, Format: conf.Format, DocType: conf.DocType,
		Credential: result.Credentials[0].Credential, HolderKey: holder,
	}, nil
}

// notify sends a Notification Request when the issuer gave the
// credential a notification_id. It's best effort: a wallet is never
// required to notify, so a failure doesn't fail receiving.
func (is issuance) notify(ctx context.Context, notificationID string, event oid4vci.NotificationEvent, description string) {
	if notificationID == "" || is.metadata.NotificationEndpoint == nil {
		return
	}
	_ = is.w.RequestNotification(ctx, is.resource, *is.metadata.NotificationEndpoint, wallet.NotificationRequest{
		NotificationID: notificationID, Event: event, EventDescription: description,
	})
}

// pending starts polling for a credential the issuer deferred.
func (is issuance) pending(configID string, holder *ecdsa.PrivateKey, result wallet.CredentialResult) (*Pending, error) {
	if is.metadata.DeferredCredentialEndpoint == nil {
		return nil, fmt.Errorf("walletapp: credential %q was deferred, but the issuer advertises no deferred credential endpoint", configID)
	}
	return &Pending{
		ConfigurationID: configID, Format: is.metadata.CredentialConfigurationsSupported[configID].Format,
		Interval: result.Interval, transactionID: result.TransactionID, holder: holder, is: is,
	}, nil
}

// Pending is a credential the issuer deferred (OID4VCI 1.0 §9): it
// holds the transaction_id, the holder key the request proved, and the
// access token to poll with, in memory.
type Pending struct {
	ConfigurationID string
	Format          string
	// Interval is how long the issuer asked the wallet to wait between
	// polls.
	Interval time.Duration

	transactionID string
	holder        *ecdsa.PrivateKey
	is            issuance
}

// Poll asks the issuer once: it returns the credential once issued
// (validated, with the issuer notified), nil while it's still pending,
// or ErrDenied.
func (p *Pending) Poll(ctx context.Context) (*Received, error) {
	result, err := p.is.w.RequestDeferredCredential(ctx, p.is.resource, *p.is.metadata.DeferredCredentialEndpoint, wallet.DeferredCredentialRequest{
		TransactionID: p.transactionID, RequestEncryption: p.is.requestEnc, ResponseEncryption: p.is.responseEnc,
	})
	var werr *wallet.Error
	switch {
	case errors.As(err, &werr) && werr.Code == "credential_request_denied":
		return nil, ErrDenied
	case err != nil:
		return nil, fmt.Errorf("walletapp: deferred credential %q: %w", p.ConfigurationID, err)
	case len(result.Credentials) == 0:
		if result.Interval > 0 {
			p.Interval = result.Interval
		}
		return nil, nil
	}
	r, err := p.is.accept(ctx, p.ConfigurationID, p.holder, result)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// Wait polls, at the issuer's interval, until the credential is issued
// or denied, or ctx is done.
func (p *Pending) Wait(ctx context.Context) (Received, error) {
	for {
		r, err := p.Poll(ctx)
		if err != nil {
			return Received{}, err
		}
		if r != nil {
			return *r, nil
		}
		select {
		case <-ctx.Done():
			return Received{}, fmt.Errorf("walletapp: waiting for deferred credential %q: %w", p.ConfigurationID, ctx.Err())
		case <-time.After(max(p.Interval, minPollInterval)):
		}
	}
}
