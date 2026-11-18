package walletflow_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/idfoundry/oid4vcgo/walletflow"
	"github.com/idfoundry/oid4vcgo/walletflow/walletflowtest"
	"github.com/idfoundry/oid4vcgo/walletprovider"
)

// refusingProvider is a Wallet Provider whose Wallet Attestations are
// refused with refusal, and its Key Attestations with keyRefusal, while
// it's set. It counts the Key Attestations asked for.
type refusingProvider struct {
	walletflow.WalletProvider
	refusal, keyRefusal atomic.Pointer[error]
	keyAttestations     atomic.Int32
}

func (p *refusingProvider) WalletAttestation(ctx context.Context, clientID string, instanceKey crypto.PublicKey) (string, error) {
	if err := p.refusal.Load(); err != nil {
		return "", *err
	}
	return p.WalletProvider.WalletAttestation(ctx, clientID, instanceKey)
}

func (p *refusingProvider) KeyAttestation(ctx context.Context, instanceKey crypto.PublicKey, keys []*ecdsa.PublicKey, nonce string) (string, error) {
	p.keyAttestations.Add(1)
	if err := p.keyRefusal.Load(); err != nil {
		return "", *err
	}
	return p.WalletProvider.KeyAttestation(ctx, instanceKey, keys, nonce)
}

// retiringRefusals are the Wallet Provider's refusals that retire an
// instance key, as a walletprovider.Client reports them, and as a
// provider that isn't one may.
func retiringRefusals() map[string]error {
	return map[string]error{
		"instance_key_expired":    &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeInstanceKeyExpired},
		"registration_expired":    &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeRegistrationExpired},
		"instance_key_registered": &walletprovider.RefusedError{Status: 409, Code: walletprovider.CodeInstanceKeyRegistered},
		// The record of the key deleted after its retention, and no
		// fresh evidence the client can make for it (Android).
		"evidence_required": &walletprovider.RefusedError{Status: 400, Code: walletprovider.CodeEvidenceRequired},
		"wrapped sentinel":  fmt.Errorf("native provider: %w", walletprovider.ErrInstanceKeyExpired),
	}
}

// newRefusingWallet is a wallet asking for refresh tokens, kept in
// grants, whose Wallet Provider is f's, behind a refusingProvider.
func newRefusingWallet(t *testing.T, f fixture, grants walletflow.GrantStore) (*walletflow.Wallet, *refusingProvider) {
	t.Helper()
	provider := &refusingProvider{WalletProvider: f.env.Provider}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, RedirectURI: walletflowtest.RedirectURI, CredentialIssuers: []string{f.env.IssuerURL}, IssuerRoots: f.env.IssuerRoots,
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
	for name, refusal := range retiringRefusals() {
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
// suspended, say, or a retiring code at a status the provider doesn't
// answer it with, as a redirect or a proxy in front of it may — keeps
// the grant: a later refresh may succeed.
func TestRefreshCredential_ProviderRefusalKeepsTheGrant(t *testing.T) {
	for name, refusal := range map[string]error{
		"instance_not_active":            &walletprovider.RefusedError{Status: 403, Code: "instance_not_active"},
		"registration_expired at 302":    &walletprovider.RefusedError{Status: 302, Code: walletprovider.CodeRegistrationExpired},
		"instance_key_expired at 404":    &walletprovider.RefusedError{Status: 404, Code: walletprovider.CodeInstanceKeyExpired},
		"instance_key_registered at 403": &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeInstanceKeyRegistered},
		"evidence_required at 307":       &walletprovider.RefusedError{Status: 307, Code: walletprovider.CodeEvidenceRequired},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			f := newFixture(t, walletflowtest.Options{})
			w, provider := newRefusingWallet(t, f, walletflow.NewMemoryGrantStore())
			c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
			provider.refusal.Store(&refusal)
			if _, _, err := w.RefreshCredential(ctx, c.ID); err == nil || errors.Is(err, walletflow.ErrReissueRequired) {
				t.Fatalf("RefreshCredential = %v, want the refusal, not ErrReissueRequired", err)
			}
			provider.refusal.Store(nil)
			if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
				t.Fatalf("RefreshCredential once the provider attests again = %v", err)
			}
		})
	}
}

// A refresh whose Wallet Attestation passes but whose Key Attestation,
// for the same instance key, is refused for good is ErrReissueRequired
// at once, as a refusal at its Wallet Attestation is: the grant and its
// instance key are forgotten, and the provider isn't asked again.
func TestRefreshCredential_KeyAttestationRetiresInstanceKey(t *testing.T) {
	for name, refusal := range retiringRefusals() {
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

			provider.keyRefusal.Store(&refusal)
			before := provider.keyAttestations.Load()
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
			if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, walletflow.ErrReissueRequired) || errors.Is(err, refusal) {
				t.Errorf("RefreshCredential again = %v, want ErrReissueRequired without asking the provider", err)
			}
			if n := provider.keyAttestations.Load() - before; n != 1 {
				t.Errorf("Key Attestations asked = %d, want 1: the provider isn't asked again", n)
			}
		})
	}
}

// A Key Attestation refusal that doesn't retire the instance key keeps
// the grant, as at the Wallet Attestation.
func TestRefreshCredential_KeyAttestationRefusalKeepsTheGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	w, provider := newRefusingWallet(t, f, walletflow.NewMemoryGrantStore())
	c := receive(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	var refusal error = &walletprovider.RefusedError{Status: 403, Code: "instance_not_active"}
	provider.keyRefusal.Store(&refusal)
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, refusal) || errors.Is(err, walletflow.ErrReissueRequired) {
		t.Fatalf("RefreshCredential = %v, want the refusal, not ErrReissueRequired", err)
	}
	provider.keyRefusal.Store(nil)
	if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
		t.Fatalf("RefreshCredential once the provider attests again = %v", err)
	}
}

// A new issuance's Key Attestation refused as registration_expired just
// fails it: its instance key is its own, no grant has it, and the next
// issuance makes another.
func TestIssuance_KeyAttestationRefusedRegistrationExpired(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{})
	w, provider := newRefusingWallet(t, f, walletflow.NewMemoryGrantStore())
	var refusal error = &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeRegistrationExpired}
	provider.keyRefusal.Store(&refusal)
	s, err := w.StartIssuance(ctx, f.env.AuthorizationCodeOffer(t, walletflowtest.SDJWTConfigurationID))
	if err != nil {
		t.Fatal(err)
	}
	authorize(t, f, s)
	if _, err := s.RequestCredentials(ctx); !errors.Is(err, walletprovider.ErrRegistrationExpired) || errors.Is(err, walletflow.ErrReissueRequired) {
		t.Errorf("RequestCredentials = %v, want the refusal as is", err)
	}
	_ = s.Close(ctx)
	provider.keyRefusal.Store(nil)
	receive(t, f, w, walletflowtest.SDJWTConfigurationID)
}

// A GrantAuthNone grant has no instance key: a refresh's Key
// Attestation is for one made for that refresh alone, so a refusal
// retiring that key leaves the grant, and the next refresh makes another.
func TestRefreshCredential_AnonymousKeyAttestationRefusalKeepsTheGrant(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t, walletflowtest.Options{Anonymous: true, AnonymousRefresh: true, JWTKeyAttestation: true})
	grants := walletflow.NewMemoryGrantStore()
	provider := &refusingProvider{WalletProvider: f.env.Provider}
	w, err := walletflow.New(walletflow.Config{
		ClientID: walletflowtest.ClientID, CredentialIssuers: []string{f.env.IssuerURL}, IssuerRoots: f.env.IssuerRoots, Development: true,
		IssuanceProfile: walletflow.ProfileOpenID4VCI, RequestRefresh: true,
	}, walletflow.Dependencies{Keys: f.keys, Credentials: f.store, HTTP: f.env.HTTP, Provider: provider, Grants: grants})
	if err != nil {
		t.Fatal(err)
	}
	c := receivePreAuthorized(t, f, w, walletflowtest.SDJWTConfigurationID)[0]
	if g, err := grants.GetGrant(ctx, c.GrantID); err != nil || g.ClientAuth != walletflow.GrantAuthNone {
		t.Fatalf("grant = %+v, %v, want a GrantAuthNone one", g, err)
	}
	var refusal error = &walletprovider.RefusedError{Status: 403, Code: walletprovider.CodeInstanceKeyExpired}
	provider.keyRefusal.Store(&refusal)
	if _, _, err := w.RefreshCredential(ctx, c.ID); !errors.Is(err, refusal) || errors.Is(err, walletflow.ErrReissueRequired) {
		t.Fatalf("RefreshCredential = %v, want the refusal, not ErrReissueRequired", err)
	}
	provider.keyRefusal.Store(nil)
	if _, _, err := w.RefreshCredential(ctx, c.ID); err != nil {
		t.Fatalf("RefreshCredential once the provider attests again = %v", err)
	}
}
