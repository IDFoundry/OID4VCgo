package walletflow_test

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// refusingProvider is a Wallet Provider whose Wallet Attestations are
// refused with refusal while it's set.
type refusingProvider struct {
	walletflow.WalletProvider
	refusal atomic.Pointer[error]
}

func (p *refusingProvider) WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	if err := p.refusal.Load(); err != nil {
		return "", *err
	}
	return p.WalletProvider.WalletAttestation(ctx, clientID, instanceKey)
}

// newRefusingWallet is a wallet asking for refresh tokens, kept in
// grants, whose Wallet Provider is f's, behind a refusingProvider.
func newRefusingWallet(t *testing.T, f fixture, grants walletflow.GrantStore) (*walletflow.Wallet, *refusingProvider) {
	t.Helper()
	provider := &refusingProvider{WalletProvider: f.env.Provider}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, IssuerRoots: f.env.IssuerRoots,
		Development: true, RequestRefresh: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, Provider: provider, HTTP: f.env.HTTP, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	return w, provider
}

// A refresh whose grant's instance key the Wallet Provider no longer
// attests — its evidence expired, the instance must register again, or
// the key is an instance's the wallet no longer is — doesn't try it
// again: the grant and its instance key are forgotten, the refresh is
// ErrReissueRequired, and a new issuance, with a new instance key,
// receives the credential again.
func TestRefreshCredential_InstanceKeyRetired(t *testing.T) {
	for name, refusal := range map[string]error{
		"instance_key_expired":    &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeInstanceKeyExpired},
		"registration_expired":    &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeRegistrationExpired},
		"instance_key_registered": &walletprovider.RefusedError{Status: 409, Code: walletprovider.CodeInstanceKeyRegistered},
		// As a provider that isn't walletprovider.Client may report it.
		"wrapped sentinel": fmt.Errorf("native provider: %w", walletprovider.ErrInstanceKeyExpired),
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, walletflowtest.Options{})
			grants := walletflow.NewMemoryGrantStore()
			w, provider := newRefusingWallet(t, f, grants)
			c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
			g, err := grants.GetGrant(ctx, c.GrantID)
			if err != nil {
				t.Fatal(err)
			}

			provider.refusal.Store(&refusal)
			_, _, err = w.RefreshCredential(ctx, c.ID)
			if !errors.Is(err, walletflow.ErrReissueRequired) || !errors.Is(err, refusal) {
				t.Fatalf("RefreshCredential = %v, want ErrReissueRequired wrapping the refusal", err)
			}
			if _, err := grants.GetGrant(ctx, g.ID); !errors.Is(err, walletflow.ErrNotFound) {
				t.Errorf("the grant was kept: %v", err)
			}
			if _, err := f.keys.Key(ctx, g.InstanceKeyID); !errors.Is(err, walletflow.ErrNotFound) {
				t.Errorf("the grant's instance key was kept: %v", err)
			}
			// Not asked again: the grant is gone.
			if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) || errors.Is(err, refusal) {
				t.Errorf("RefreshCredential again = %v, want ErrReissueRequired without asking the provider", err)
			}

			provider.refusal.Store(nil)
			again := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
			g2, err := grants.GetGrant(ctx, again.GrantID)
			if err != nil {
				t.Fatal(err)
			}
			if g2.InstanceKeyID == g.InstanceKeyID {
				t.Errorf("the new issuance reused the retired instance key %s", g.InstanceKeyID)
			}
		})
	}
}

// A refusal that doesn't retire the instance key — the instance
// suspended, say — keeps the grant: a later refresh may succeed.
func TestRefreshCredential_ProviderRefusalKeepsTheGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	w, provider := newRefusingWallet(t, f, walletflow.NewMemoryGrantStore())
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	var refusal error = &walletprovider.RefusedError{Status: 403, Code: "instance_not_active"}
	provider.refusal.Store(&refusal)
	if _, _, err := w.RefreshCredential(ctx, c.ID); err == nil || errors.Is(err, walletflow.ErrReissueRequired) {
		t.Fatalf("RefreshCredential = %v, want the refusal, not ErrReissueRequired", err)
	}
	provider.refusal.Store(nil)
	if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
		t.Fatalf("RefreshCredential once the provider attests again = %v", err)
	}
}
