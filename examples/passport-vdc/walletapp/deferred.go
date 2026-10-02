package walletapp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/idfoundry/oid4vcgo/walletflow"
)

// ErrDenied is returned for a deferred credential the issuer refused
// (OID4VCI 1.0 §9.3, credential_request_denied).
var ErrDenied = walletflow.ErrCredentialDenied

// minPollInterval is the shortest wait between polls, whatever interval
// the issuer asks for.
const minPollInterval = time.Second

// Pending is a credential the issuer deferred (OID4VCI 1.0 §9), polled
// with the issuance's access token, in memory.
type Pending struct {
	ConfigurationID string
	Format          string
	// Interval is how long the issuer asked the wallet to wait between
	// polls.
	Interval time.Duration

	d     *walletflow.Deferred
	keys  *softwareKeys
	group *pendingGroup
}

// pendingGroup closes an issuance once every credential it deferred is
// settled.
type pendingGroup struct {
	mu        sync.Mutex
	s         *walletflow.Issuance
	remaining int
}

func (g *pendingGroup) settled(ctx context.Context) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.remaining--; g.remaining == 0 {
		_ = g.s.Close(ctx)
	}
}

func newPendings(s *walletflow.Issuance, keys *softwareKeys, deferred []*walletflow.Deferred) []*Pending {
	formats := map[string]string{}
	for _, c := range s.Offer().Credentials {
		formats[c.ConfigurationID] = c.Format
	}
	group := &pendingGroup{s: s, remaining: len(deferred)}
	out := make([]*Pending, 0, len(deferred))
	for _, d := range deferred {
		out = append(out, &Pending{
			ConfigurationID: d.ConfigurationID(), Format: formats[d.ConfigurationID()],
			Interval: d.Interval(), d: d, keys: keys, group: group,
		})
	}
	return out
}

// Poll asks the issuer once: it returns the credential once issued
// (validated, with the issuer notified), nil while it's still pending,
// or ErrDenied.
func (p *Pending) Poll(ctx context.Context) (*Received, error) {
	stored, err := p.d.Poll(ctx)
	switch {
	case errors.Is(err, walletflow.ErrCredentialDenied):
		p.group.settled(ctx)
		return nil, ErrDenied
	case err != nil:
		return nil, fmt.Errorf("walletapp: %w", err)
	case stored == nil:
		p.Interval = p.d.Interval()
		return nil, nil
	}
	r := p.keys.received(*stored)
	p.group.settled(ctx)
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
