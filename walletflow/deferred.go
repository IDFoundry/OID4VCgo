package walletflow

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/idfoundry/oid4vcgo/wallet"
)

// minPollInterval is the shortest wait between Wait's polls, whatever
// interval the issuer asks for.
const minPollInterval = time.Second

// Deferred is a credential the issuer will issue later (OpenID4VCI 1.0
// §9). It's polled with the issuance's access token, so only until the
// Issuance is closed.
type Deferred struct {
	s             *Issuance
	configID      string
	holder        Key
	transactionID string
	interval      time.Duration
	requestEnc    *wallet.RequestEncryption
	responseEnc   *wallet.ResponseEncryption
	done          bool
}

// Done reports whether the Deferred is settled — issued, denied, or
// refused by the wallet's checks — or its Issuance closed: polling it
// again returns ErrWrongStep.
func (d *Deferred) Done() bool {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	return d.done || d.s.step == stepClosed
}

// ConfigurationID is the credential configuration deferred.
func (d *Deferred) ConfigurationID() string { return d.configID }

// Interval is how long the issuer asked the wallet to wait between
// polls.
func (d *Deferred) Interval() time.Duration {
	d.s.mu.Lock()
	defer d.s.mu.Unlock()
	return d.interval
}

// Poll asks the issuer once. It returns the credential once issued
// (checked, stored, and the issuer notified), nil while it's still
// pending, or ErrCredentialDenied. Once it has returned the credential,
// ErrCredentialDenied, or an issued credential failing the wallet's
// checks, the Deferred is done (Done), and Poll returns ErrWrongStep;
// after any other error — a request that failed — it can be polled
// again.
func (d *Deferred) Poll(ctx context.Context) (*StoredCredential, error) {
	s := d.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if d.done || s.step == stepClosed {
		return nil, ErrWrongStep
	}
	result, err := s.w.core.RequestDeferredCredential(ctx, s.resource, *s.metadata.DeferredCredentialEndpoint, wallet.DeferredCredentialRequest{
		TransactionID: d.transactionID, RequestEncryption: d.requestEnc, ResponseEncryption: d.responseEnc,
	})
	var werr *wallet.Error
	switch {
	case errors.As(err, &werr) && werr.Code == "credential_request_denied":
		d.finish(ctx)
		return nil, ErrCredentialDenied
	case err != nil:
		return nil, fmt.Errorf("walletflow: deferred credential %q: %w", d.configID, err)
	case len(result.Credentials) == 0:
		if result.Interval > 0 {
			d.interval = result.Interval
		}
		return nil, nil
	}
	stored, err := s.accept(ctx, d.configID, d.holder, result)
	if err != nil {
		d.finish(ctx)
		return nil, err
	}
	d.done = true
	return &stored, nil
}

// finish ends a Deferred that won't yield a credential, deleting its
// holder key.
func (d *Deferred) finish(ctx context.Context) {
	d.done = true
	_ = d.s.w.deps.Keys.DeleteKey(ctx, d.holder.ID())
}

// Wait polls, at the issuer's interval, until the credential is issued
// or denied, or ctx is done.
func (d *Deferred) Wait(ctx context.Context) (StoredCredential, error) {
	for {
		stored, err := d.Poll(ctx)
		if err != nil {
			return StoredCredential{}, err
		}
		if stored != nil {
			return *stored, nil
		}
		select {
		case <-ctx.Done():
			return StoredCredential{}, fmt.Errorf("walletflow: waiting for deferred credential %q: %w", d.configID, ctx.Err())
		case <-time.After(max(d.Interval(), minPollInterval)):
		}
	}
}
